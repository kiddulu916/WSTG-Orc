# wstg_orchestrator/modules/api_testing.py
import json
import re

from wstg_orchestrator.modules.base_module import BaseModule
from wstg_orchestrator.utils.command_runner import CommandRunner
from wstg_orchestrator.utils.parser_utils import diff_responses


class ApiTestingModule(BaseModule):
    PHASE_NAME = "api_testing"
    SUBCATEGORIES = ["api_discovery", "bola_testing", "graphql_testing"]
    EVIDENCE_SUBDIRS = [
        "tool_output", "raw_requests", "raw_responses", "parsed",
        "evidence", "potential_exploits", "confirmed_exploits", "screenshots",
    ]

    SWAGGER_PATHS = [
        "/swagger.json", "/openapi.json", "/api-docs",
        "/swagger/v1/swagger.json", "/v1/swagger.json",
        "/v2/swagger.json", "/api/swagger.json",
        "/swagger-ui.html", "/swagger-resources",
        "/openapi/v3/api-docs", "/api/v1/openapi.json",
        "/docs", "/redoc", "/.well-known/openapi.json",
    ]

    API_VERSION_PATHS = [
        "/api/v{n}/", "/v{n}/api/", "/api/{n}/",
    ]

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            types {
                name
                kind
                fields {
                    name
                    type { name kind }
                    args { name type { name } }
                }
            }
        }
    }
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cmd = CommandRunner(
            tool_configs={
                name: self.config.get_tool_config(name)
                for name in ["kiterunner"]
            }
        )

    async def execute(self):
        if not self.should_skip_subcategory("api_discovery"):
            await self._api_discovery()
            self.mark_subcategory_complete("api_discovery")

        if not self.should_skip_subcategory("bola_testing"):
            await self._bola_testing()
            self.mark_subcategory_complete("bola_testing")

        if not self.should_skip_subcategory("graphql_testing"):
            await self._graphql_testing()
            self.mark_subcategory_complete("graphql_testing")

    async def _api_discovery(self):
        self.logger.info("Starting API discovery")
        live_hosts = self.state.get("live_hosts") or []
        found_apis = []

        for host_url in live_hosts:
            base = host_url.rstrip("/")

            # Swagger/OpenAPI detection
            for path in self.SWAGGER_PATHS:
                try:
                    resp = self._http_get(f"{base}{path}")
                    if resp.status_code == 200:
                        content_type = resp.headers.get("Content-Type", "")
                        if "json" in content_type or resp.text.strip().startswith("{"):
                            try:
                                spec = json.loads(resp.text)
                                if "swagger" in spec or "openapi" in spec or "paths" in spec:
                                    self.logger.info(f"Found OpenAPI spec at {base}{path}")
                                    self.evidence.log_tool_output("api_testing", "swagger_spec", resp.text)
                                    # Extract endpoints from spec
                                    paths = spec.get("paths", {})
                                    for api_path, methods in paths.items():
                                        full_url = f"{base}{api_path}"
                                        found_apis.append(full_url)
                                        for method_name in methods:
                                            if method_name.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                                self.evidence.log_parsed("api_testing", "api_endpoint", {
                                                    "url": full_url, "method": method_name.upper(),
                                                })
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    continue

            # API version rollback
            for version_template in self.API_VERSION_PATHS:
                for n in range(1, 5):
                    version_path = version_template.replace("{n}", str(n))
                    try:
                        resp = self._http_get(f"{base}{version_path}")
                        if resp.status_code in [200, 301, 302]:
                            found_apis.append(f"{base}{version_path}")
                    except Exception:
                        continue

        # Kiterunner
        if self._cmd.is_tool_available("kiterunner"):
            for host_url in live_hosts[:3]:
                result = self._cmd.run(
                    "kiterunner", ["scan", host_url, "--fail-status-codes", "404,400"],
                    timeout=300,
                )
                if result.returncode == 0:
                    self.evidence.log_tool_output("api_testing", "kiterunner", result.stdout)
                    for line in result.stdout.splitlines():
                        url_match = re.search(r'(https?://\S+)', line)
                        if url_match:
                            found_apis.append(url_match.group(1))

        if found_apis:
            self.state.enrich("api_endpoints", list(set(found_apis)))
            self.state.enrich("endpoints", list(set(found_apis)))
            self.evidence.log_parsed("api_testing", "discovered_apis", list(set(found_apis)))

    async def _bola_testing(self):
        self.logger.info("Starting BOLA testing")
        api_endpoints = self.state.get("api_endpoints") or []
        idor_candidates = self.state.get("potential_idor_candidates") or []

        # Find API endpoints with IDs
        id_pattern = re.compile(r'/(\d+)(?:/|$|\?)')
        for endpoint in api_endpoints:
            match = id_pattern.search(endpoint)
            if match:
                original_id = match.group(1)
                for test_id in [str(int(original_id) + 1), str(int(original_id) - 1), "1"]:
                    test_url = endpoint.replace(f"/{original_id}", f"/{test_id}")
                    try:
                        original_resp = self._http_get(endpoint)
                        test_resp = self._http_get(test_url)

                        if test_resp.status_code == 200 and original_resp.status_code == 200:
                            diff = diff_responses(original_resp.text, test_resp.text)
                            if not diff["identical"]:
                                self.evidence.log_potential_exploit("api_testing", {
                                    "type": "bola",
                                    "original_url": endpoint,
                                    "test_url": test_url,
                                    "severity": "high",
                                    "description": "Potential BOLA: API returned different data for different IDs",
                                })
                                self.state.enrich("potential_vulnerabilities", [{
                                    "type": "bola",
                                    "url": test_url,
                                    "severity": "high",
                                    "description": f"BOLA: ID swap from {original_id} to {test_id} returned data",
                                }])
                    except Exception:
                        continue

    async def _graphql_testing(self):
        self.logger.info("Starting GraphQL testing")
        live_hosts = self.state.get("live_hosts") or []
        endpoints = self.state.get("endpoints") or []

        graphql_endpoints = [
            ep for ep in endpoints + live_hosts
            if "graphql" in ep.lower()
        ]

        # Also probe common GraphQL paths
        for host_url in live_hosts:
            base = host_url.rstrip("/")
            for path in ["/graphql", "/graphiql", "/gql", "/api/graphql"]:
                try:
                    resp = self._http_post(f"{base}{path}", json_data={"query": "{ __typename }"})
                    if resp.status_code == 200 and "__typename" in resp.text:
                        graphql_endpoints.append(f"{base}{path}")
                except Exception:
                    continue

        graphql_endpoints = list(set(graphql_endpoints))

        for endpoint in graphql_endpoints:
            # Introspection query
            try:
                resp = self._http_post(endpoint, json_data={"query": self.INTROSPECTION_QUERY})
                if resp.status_code == 200 and "__schema" in resp.text:
                    self.logger.info(f"GraphQL introspection enabled at {endpoint}")
                    self.evidence.log_tool_output("api_testing", "graphql_schema", resp.text)

                    try:
                        schema = json.loads(resp.text)
                        types = schema.get("data", {}).get("__schema", {}).get("types", [])
                        self.evidence.log_parsed("api_testing", "graphql_types", {
                            "endpoint": endpoint,
                            "type_count": len(types),
                            "types": [t.get("name") for t in types if not t.get("name", "").startswith("__")],
                        })
                    except json.JSONDecodeError:
                        pass

                    self.state.enrich("potential_vulnerabilities", [{
                        "type": "graphql_introspection",
                        "url": endpoint,
                        "severity": "low",
                        "description": "GraphQL introspection enabled — full schema is queryable",
                    }])

                    # Depth abuse test
                    depth_query = self._build_depth_query(5)
                    try:
                        depth_resp = self._http_post(endpoint, json_data={"query": depth_query})
                        if depth_resp.status_code == 200 and "errors" not in depth_resp.text.lower():
                            self.evidence.log_potential_exploit("api_testing", {
                                "type": "graphql_depth_abuse",
                                "url": endpoint,
                                "depth": 5,
                                "severity": "medium",
                                "description": "GraphQL allows deeply nested queries (no depth limit)",
                            })
                    except Exception:
                        pass
            except Exception as e:
                self.logger.debug(f"GraphQL test failed for {endpoint}: {e}")

    def _build_depth_query(self, depth: int) -> str:
        query = "{ __typename }"
        for i in range(depth):
            query = f"{{ __schema {{ types {{ fields {{ type {{ ofType {query} }} }} }} }} }}"
        return query

    def _http_get(self, url: str, extra_headers: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.get(url, headers=extra_headers)

    def _http_post(self, url: str, data: dict | None = None, json_data: dict | None = None):
        from wstg_orchestrator.utils.http_utils import HttpClient
        client = HttpClient(
            scope_checker=self.scope,
            rate_limiter=self.rate_limiter,
            custom_headers=self.config.custom_headers if hasattr(self.config, 'custom_headers') else {},
        )
        return client.post(url, data=data, json_data=json_data)