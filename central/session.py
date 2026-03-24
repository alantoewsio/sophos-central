import logging
from urllib.parse import urlencode, urljoin
import requests
from central.classes import (
    AuthenticationResponse,
    ReturnState,
    CentralResponse,
    PaginationRequest,
    Tenant,
    Tenants,
    WhoamiResponse,
)

# Sophos Central API URL (https://developer.sophos.com/getting-started)
_auth_url = "https://id.sophos.com/api/v2/oauth2/token"
_whoami_url = "https://api.central.sophos.com/whoami/v1"

# Default timeout in seconds for HTTP requests (avoids hanging on unresponsive servers).
_REQUEST_TIMEOUT = 30

logger = logging.getLogger(__name__)


class CentralSession:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.jwt = None
        self.auth: AuthenticationResponse = None
        self.whoami: WhoamiResponse = None
        self.tenants: Tenants = []

    def _do_authenticate(self) -> ReturnState:
        if self.client_id is None or self.client_secret is None:
            logger.error("Client ID or Client Secret is not set")
            return ReturnState(
                success=False, message="Client ID or Client Secret is not found"
            )

        logger.debug("Posting token request to %s", _auth_url)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = f"grant_type=client_credentials&client_id={self.client_id}&client_secret={self.client_secret}&scope=token"
        response = requests.post(
            _auth_url, headers=headers, data=payload, timeout=_REQUEST_TIMEOUT
        )
        if response.status_code != 200:
            logger.error(
                "Authentication failed: status=%s body=%s",
                response.status_code,
                response.text[:200],
            )
            return ReturnState(
                success=False,
                message=f"Authentication failed: {response.status_code} {response.text}",
            )

        auth_data = response.json()
        logger.debug("Auth response keys: %s", list(auth_data.keys()))
        self.auth = AuthenticationResponse(**auth_data)
        self.jwt = self.auth.access_token
        logger.info("Auth success; token valid=%s", self.auth.is_valid())
        return ReturnState(success=True)

    def _do_whoami(self) -> ReturnState:
        if self.jwt is None:
            logger.error("JWT is not set; cannot call whoami")
            raise Exception("Authentication failed: JWT is not found")

        logger.debug("Calling whoami: %s", _whoami_url)
        headers = {"Authorization": f"Bearer {self.jwt}"}
        response = requests.get(
            _whoami_url, headers=headers, timeout=_REQUEST_TIMEOUT
        )
        if response.status_code != 200:
            logger.error(
                "Whoami failed: status=%s body=%s",
                response.status_code,
                response.text[:200],
            )
            return ReturnState(
                success=False,
                message=f"Authentication failed: {response.status_code} {response.text}",
            )

        whoami_data = response.json()
        logger.debug(
            "Whoami response: idType=%s id=%s",
            whoami_data.get("idType"),
            whoami_data.get("id"),
        )
        self.whoami = WhoamiResponse(**whoami_data)
        return ReturnState(success=True)

    def authenticate(self) -> ReturnState:
        if self.auth:
            return ReturnState(success=True)

        auth_result = self._do_authenticate()

        if not auth_result:
            return auth_result

        return self._do_whoami()

    def _do_get_tenants(self) -> ReturnState:
        if not self.auth and not self.authenticate():
            return ReturnState(success=False, message="Error: not authenticated")
        # headers = {"Authorization": f"Bearer {self.jwt}"}
        response = self.get("/partner/v1/tenants", partner_id=self.whoami.id)
        if not response.success:
            return response
        # print(f"Found {len(response.value)} tenants")
        self.tenants = Tenants([Tenant(**tenant) for tenant in response.value])
        return ReturnState(success=True)

    def get_tenants(self) -> Tenants | ReturnState:
        if self.whoami.idType == "tenant":
            return ReturnState(
                success=False,
                value=[],
                message="Error: tenants do not have sub-tenants",
            )
        if not self.tenants and self._do_get_tenants():
            return self.tenants
        return ReturnState(success=False, value=[], message="Error: tenants not found")

    def _get_url(
        self,
        url_path: str,
        url_base: str = None,
        params: dict = None,
    ) -> str:
        # Tenant creds are given a global and base url in whoami response
        # Partner and organization creds are only given a global url,
        # and must fetch tenant records to get the tenant dataregion
        full_url = ""

        if self.whoami.idType == "tenant":
            full_url = url_base or self.whoami.data_region_url()
        else:
            full_url = url_base or self.whoami.global_url()
        if params:
            # doseq=True so list values become repeated keys (e.g. product=firewall&product=other)
            full_url_path = f"{url_path}?{urlencode(params, doseq=True)}"
        else:
            full_url_path = url_path
        result = urljoin(full_url, full_url_path)
        logger.debug("Built URL: %s (path=%s, base=%s)", result, url_path, url_base)
        return result

    def _add_base_headers(
        self,
        tenant_id: str = None,
        partner_id: str = None,
        organization_id: str = None,
        **added_headers: str,
    ) -> dict:

        headers = {}
        if self.jwt:
            headers["Authorization"] = f"Bearer {self.jwt}"
        if tenant_id is not None:
            headers["X-Tenant-ID"] = tenant_id
        if partner_id is not None:
            headers["X-Partner-ID"] = partner_id
        if organization_id is not None:
            headers["X-Organization-ID"] = organization_id
        for k, v in added_headers.items():
            headers[k] = v

        logger.debug(
            "Headers jwt-len=%s tenant_id=%s partner_id=%s org_id=%s",
            len(self.jwt) if self.jwt else 0,
            tenant_id,
            partner_id,
            organization_id,
        )

        return headers

    def get(
        self,
        url_path: str,
        params: dict = None,
        url_base: str = None,
        tenant_id: str = None,
        partner_id: str = None,
        organization_id: str = None,
        paginated: bool = True,
    ) -> ReturnState:
        if not self.auth and not self.authenticate():
            logger.error("Not authenticated; cannot perform get")
            return ReturnState(success=False, message="Error: not authenticated")

        logger.debug(
            "GET %s (tenant_id=%s partner_id=%s)", url_path, tenant_id, partner_id
        )
        result = self.get_page(
            url_path,
            params,
            tenant_id=tenant_id,
            partner_id=partner_id,
            organization_id=organization_id,
            url_base=url_base,
            paginated=paginated,
        )
        if not result.success:
            return result

        items = result.value.items if result.value.items is not None else []
        if hasattr(result.value, "pages") and result.value.pages:
            pages = result.value.pages
            next_key = getattr(pages, "nextKey", None)
            if next_key is not None:
                # Key-based pagination (e.g. Common API alerts)
                while next_key:
                    logger.debug(
                        "Fetching next page of %s (key=%s)", url_path, next_key
                    )
                    page_params = dict(params or {})
                    page_params["pageFromKey"] = next_key
                    result = self.get_page(
                        url_path,
                        params=page_params,
                        tenant_id=tenant_id,
                        partner_id=partner_id,
                        organization_id=organization_id,
                        url_base=url_base,
                        paginated=False,
                    )
                    if not result.success:
                        return result
                    if result.value.items:
                        items.extend(result.value.items)
                    next_key = (
                        getattr(result.value.pages, "nextKey", None)
                        if getattr(result.value, "pages", None)
                        else None
                    )
            else:
                # Page-number pagination (only when pages has current/total)
                page_num = 1
                total = getattr(pages, "total", None)
                current = getattr(pages, "current", None)
                while (
                    result
                    and total is not None
                    and current is not None
                    and current < total
                ):
                    page_num += 1
                    logger.debug("Fetching page %d of %s", page_num, url_path)
                    result = self.get_page(
                        url_path=url_path,
                        params=params,
                        page=page_num,
                        tenant_id=tenant_id,
                        partner_id=partner_id,
                        organization_id=organization_id,
                        url_base=url_base,
                        paginated=paginated,
                    )
                    if not result.success:
                        return result
                    items.extend(result.value.items)
                    pages = result.value.pages
                    current = getattr(pages, "current", None)
                    total = getattr(pages, "total", None)
        logger.debug("GET %s returned %d items", url_path, len(items) if items else 0)
        return ReturnState(success=True, value=items)

    def get_page(
        self,
        url_path: str,
        params: dict = None,
        page: int = 1,
        pageSize: int = 100,
        url_base: str = None,
        tenant_id: str = None,
        partner_id: str = None,
        organization_id: str = None,
        paginated: bool = True,
    ) -> ReturnState:
        if not self.auth and not self.authenticate():
            return ReturnState(success=False, message="Error: not authenticated")

        pages = PaginationRequest(page=page, pageSize=pageSize, pageTotal=True)

        params = params or {}
        if paginated:
            params.update(pages.__dict__)

        full_url = self._get_url(url_path, url_base, params)
        headers = self._add_base_headers(
            tenant_id=tenant_id,
            partner_id=partner_id,
            organization_id=organization_id,
        )

        logger.debug(
            "GET request: url=%s page=%s pageSize=%s", full_url, page, pageSize
        )
        # if "X-Tenant-ID" in headers:
        #   print(f"get from url: {full_url} - tenant: {headers['X-Tenant-ID']}")
        # if "X-Partner-ID" in headers:
        #     print(f"get from url: {full_url} - partner: {headers['X-Partner-ID']}")
        response = requests.get(
            full_url, headers=headers, timeout=_REQUEST_TIMEOUT
        )
        central_response = CentralResponse(response)
        if not central_response.success:
            logger.debug(
                "GET %s status=%s error=%s",
                url_path,
                central_response.status_code,
                central_response.error_message,
            )
        return ReturnState(success=central_response.success, value=central_response)

    def patch(
        self,
        url_path: str,
        params: dict = None,
        payload: dict = None,
        url_base: str = None,
        tenant_id: str = None,
        partner_id: str = None,
        organization_id: str = None,
    ) -> ReturnState:
        if not self.auth and not self.authenticate():
            return ReturnState(success=False, message="Error: not authenticated")

        full_url = self._get_url(
            url_path=url_path, url_base=url_base, params=params
        )
        headers = self._add_base_headers(tenant_id=tenant_id)

        response = requests.patch(
            full_url, headers=headers, json=payload, timeout=_REQUEST_TIMEOUT
        )
        central_response = CentralResponse(response)
        return ReturnState(success=central_response.success, value=central_response)

    def post(
        self,
        url_path: str,
        params: dict = None,
        payload: dict = None,
        url_base: str = None,
        tenant_id: str = None,
        partner_id: str = None,
        organization_id: str = None,
    ) -> ReturnState:
        if not self.auth and not self.authenticate():
            return ReturnState(success=False, message="Error: not authenticated")
        full_url = self._get_url(url_base=url_base, url_path=url_path, params=params)
        headers = self._add_base_headers(
            tenant_id=tenant_id,
            partner_id=partner_id,
            organization_id=organization_id,
        )

        response = requests.post(
            full_url, headers=headers, json=payload, timeout=_REQUEST_TIMEOUT
        )
        central_response = CentralResponse(response)
        return ReturnState(success=central_response.success, value=central_response)

    def delete(
        self,
        url_path: str,
        params: dict = None,
        payload: dict = None,
        url_base: str = None,
        tenant_id: str = None,
        partner_id: str = None,
        organization_id: str = None,
    ) -> ReturnState:
        if not self.auth and not self.authenticate():
            return ReturnState(success=False, message="Error: not authenticated")
        full_url = self._get_url(
            url_path=url_path, url_base=url_base, params=params
        )
        headers = self._add_base_headers(
            tenant_id=tenant_id,
            partner_id=partner_id,
            organization_id=organization_id,
        )
        response = requests.delete(
            full_url, headers=headers, json=payload, timeout=_REQUEST_TIMEOUT
        )
        central_response = CentralResponse(response)
        return ReturnState(success=central_response.success, value=central_response)
