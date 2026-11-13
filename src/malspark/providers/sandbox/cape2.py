"""CAPEv2 sandbox behind the provider contract.

A thin seam over ``CAPEv2Client``: the REST quirks it absorbs (three submit
response shapes, transient polls that are a busy sandbox rather than a
failure, the 24-byte empty-PCAP floor) are measured behaviour and are not
re-implemented here.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from langchain_core.tools import BaseTool

from malspark.core import builtin_declarations
from malspark.core.logger import logger
from malspark.core.settings_overrides import redact_url
from malspark.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from malspark.providers.registry import register_sandbox_provider
from malspark.providers.sandbox.readers import required_reader
from malspark.providers.submission import mask_submitted, reraise_masked

# The registered report reader (``providers.sandbox.readers``) this provider's
# reports are read by.
_READER = "cape2"

# CAPE's own option string: the form field, the separator between its
# ``key=value`` entries (CAPE splits at every comma, then at the first ``=``),
# and the option its packages read the started process's arguments from.
_OPTIONS_FIELD = "options"
_OPTION_SEPARATOR = ","
_ARGUMENTS_OPTION = "arguments"

# The CAPEv2 analysis packages whose documented options include ``arguments``
# (CAPEv2 documentation, "Analysis Packages" page, usage/packages.html: ``exe``,
# ``ollydbg``, ``python``, ``rar``, ``regsvr``, ``service``, ``service_dll``
# "specify any command line argument to pass to the initial process";
# ``archive``, ``dll``, ``zip``, ``zip_compound`` "specify arguments to pass to
# the DLL through commandline"). This list only says which packages are
# documented to read the option: a package outside it still gets the arguments,
# and the record says that whether it reads them is not documented. Read 2026-11-13.
_ARGUMENT_PACKAGES = frozenset(
    {
        "archive",
        "dll",
        "exe",
        "ollydbg",
        "python",
        "rar",
        "regsvr",
        "service",
        "service_dll",
        "zip",
        "zip_compound",
    }
)

# Packages the documentation positively states take no ``arguments`` option:
# none is stated in so many words, so none is listed, and no package is
# withheld the arguments on the strength of a list that is silent about it.
_NO_ARGUMENT_PACKAGES: frozenset[str] = frozenset()

if TYPE_CHECKING:
    from malspark.core.config import SandboxCape2Config, Settings
    from malspark.providers.servers import ServerHandle
    from malspark.providers.submission import LaunchArgumentsAnswer, SubmissionOptions
    from malspark.schemas.sandbox_report import SandboxRun


def _probe_refusal(response: Any) -> str | None:
    """The reason CAPE's ``{"error": true}`` envelope states for the probe, or ``None``.

    The probe asks about task 1, which need not exist: CAPE saying the task
    was not found still proves the URL and the token, so that envelope is no
    refusal. Any other envelope (an API that is disabled, a token CAPE refused
    in words) is, with the reason CAPE stated. A body that is not JSON keeps
    the status code's answer.
    """
    from malspark.loaders.cape2_client import CAPEv2Client
    from malspark.loaders.sandbox_client import SandboxError

    try:
        data = response.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    try:
        CAPEv2Client.raise_for_envelope(data, "probe")
    except SandboxError as exc:
        reason = " ".join(redact_url(str(exc)).splitlines())
        return None if "not found" in reason.lower() else reason
    return None


# The guest platforms this adapter's sandbox names, in our platform vocabulary
# (``extractors.sample_identity.infer_platform``): the adapter's own words for
# its guests, kept with the adapter that sends them. A platform it has no word
# for is left unset rather than guessed at, so CAPE picks the guest itself
# instead of being sent to one that cannot run the sample.
CAPE_PLATFORMS: dict[str, str] = {
    "windows": "windows",
    "linux": "linux",
    "android": "android",
}


def cape_platform(platform: str) -> str:
    """The CAPE guest platform name for one of ours, or an empty string."""
    return CAPE_PLATFORMS.get((platform or "").strip().lower(), "")


@register_sandbox_provider("cape2")
class CAPE2SandboxProvider(SandboxProvider):
    """CAPEv2 behind the provider contract.

    A thin seam over ``CAPEv2Client``: the REST quirks it absorbs (three submit
    response shapes, transient polls that are a busy sandbox rather than a
    failure, the 24-byte empty-PCAP floor) are measured behaviour and are not
    re-implemented here.
    """

    # What the console calls this provider and says about it, and its test's label.
    choice_label = "CAPE v2"
    guide_leaves = (
        "api_token",
        "base_url",
        "poll_interval_seconds",
        "timeout_seconds",
    )
    guide_advanced_leaves = ("mcp.",)
    choice_order = 1
    title = "CAPEv2"
    description = "A CAPEv2 instance detonates the sample and returns its report."
    probe_label = "Test CAPE connection"
    settings_intro = "The API token is stored on the server and never shown again."

    # The tool-facing body of the dynamic system prompt: the CAPE MCP block's
    # declared workflow (``sandbox.cape2.mcp.prompt_fragment``, shipped as
    # ``core.builtin_declarations.CAPE_WORKFLOW``), verbatim lines 25-36 of the
    # old ``_ISR_SYSTEM`` in ``dynamic_analyst.py``. ``_DYN_HEAD`` in the
    # analyst supplies the provider-independent opening this fragment
    # completes. It is sent only where the sandbox's own tools are attached
    # (``dynamic_analyst.sandbox_provider_parts``).
    CAPE_PROMPT_FRAGMENT: ClassVar[str] = builtin_declarations.CAPE_WORKFLOW

    def __init__(self, cfg: SandboxCape2Config, settings: Settings | None = None) -> None:
        self._cfg = cfg
        # The deployment's settings, for the breaker every server's guard
        # reads (``mcp.breaker``); none, and the guard takes its defaults.
        self._settings = settings
        self._client: Any = None
        self._handle: ServerHandle | None = None
        # The job this provider serves, set by the job's container
        # (``ServiceContainer.get_sandbox_provider``): what the server's
        # process is measured under for the run's isolation part, and cleared
        # with the job. Empty outside a job, and then nothing is noted.
        self.job_key = ""

    @classmethod
    def from_settings(cls, cfg: Settings) -> CAPE2SandboxProvider:
        return cls(cfg.sandbox.cape2, cfg)

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_report=True,
            can_fetch_pcap=True,
            provides_tools=bool(self._cfg.mcp.enabled),
            report_format=_READER,
            degrade_on_failure=True,
            can_pass_launch_arguments=True,
        )

    def dynamic_prompt_fragment(self) -> str:
        """The workflow text the CAPE MCP block declares, whether or not the server is up.

        The analyst sends it only where the sandbox's own tools are in the
        request (``dynamic_analyst.sandbox_provider_parts``); a disabled or
        unreachable MCP server degrades the *tools* (``dynamic_tools`` below).
        """
        return str(getattr(self._cfg.mcp, "prompt_fragment", "") or "")

    def dynamic_tools(self) -> list[BaseTool]:
        """The CAPE MCP server's tools, narrowed only by ``mcp.tools``; none while disabled.

        ``mcp.tools`` follows the ``ServerHandle.tools()`` contract: ``None``
        exposes every tool the server advertises, a list keeps those names.

        The server is attached through the one lifecycle every MCP server
        shares (``providers.servers.ServerHandle``): the job's breaker and call
        budget (``mcp.breaker`` and the block's own ``call_timeout_seconds``
        and ``tool_facts``), the block's declared ``error_patterns`` on every
        answer, the allowed environment (``env_allow``), the measured child for
        the run's isolation part, and the bounded close with its reap. It used
        to build a bare toolkit of its own, with none of them.

        Idempotent: a repeat call reuses the attached server rather than
        opening a second one, which would leak the first transport or child.
        """
        if not self._cfg.mcp.enabled:
            logger.info("CAPEv2 MCP is disabled in config.")
            return []
        block = self._cfg.mcp
        if block.transport in ("http", "streamable-http", "sse") and not block.url:
            # Remote CAPE MCP server (one started on the sandbox host with
            # --transport streamable-http) with no address to reach.
            logger.warning(
                "CAPE MCP transport=%s but sandbox.cape2.mcp.url is empty; skipping MCP init.",
                block.transport,
            )
            return []
        handle = self._server()
        if not handle.is_open:
            logger.info(
                "Initializing CAPEv2 MCP over %s%s",
                block.transport,
                f": {redact_url(block.url)}" if block.url else "",
            )
        # Opened on the shared agent loop (``ServerHandle.open``), the loop
        # the ReAct tool calls later run on, so the toolkit's session is bound
        # to it.
        handle.open(self.job_key)
        tools = handle.tools()
        logger.info("Initialized CAPEv2 MCP tools: %d: %s", len(tools), [t.name for t in tools])
        return tools

    def _server(self) -> ServerHandle:
        """This provider's CAPE MCP server handle, built once with the job's guard."""
        if self._handle is not None:
            return self._handle
        from malspark.providers.server_guard import guard_from_settings
        from malspark.providers.servers import ServerHandle

        block = self._cfg.mcp
        if block.transport == "stdio" and not block.cwd:
            # The child has always started in the project root, which is
            # where its relative arguments are resolved; a copy says so
            # rather than writing to the operator's settings leaf.
            from malspark.core.paths import get_project_root

            block = block.model_copy(update={"cwd": str(get_project_root())})
        handle = ServerHandle(self.id, block)
        # Its calls are recorded under this provider's block, and its process
        # is measured for the run's isolation part, as a job's server is.
        from malspark.agents.prompt_fragments import provider_source

        handle.declared_source = provider_source(self)
        handle.measures_isolation = True
        handle.guard = guard_from_settings(
            self.id,
            self._settings,
            sample_open=getattr(block, "sample_open", None),
            block=block,
        )
        # The deployment's settings, for what a launch hands a declared tool.
        handle.settings = self._settings
        self._handle = handle
        return handle

    @property
    def server_handle(self) -> Any:
        """The attached CAPE MCP server's handle, for the analyst's bounded ``aclose``.

        ``None`` before an attach. Closed through it, the server goes the way
        every server does; ``close`` below then finds nothing left to close.
        """
        handle = self._handle
        return handle if handle is not None and handle.is_open else None

    @property
    def _toolkit(self) -> Any:
        """The attached server's toolkit, ``None`` before an attach or after the close."""
        handle = self._handle
        return getattr(handle, "_toolkit", None) if handle is not None else None

    def _get_client(self) -> Any:
        if self._client is None:
            from malspark.loaders.cape2_client import CAPEv2Client

            self._client = CAPEv2Client(base_url=self._cfg.base_url, api_token=self._cfg.api_token)
        return self._client

    def submission_address(self) -> str | None:
        """The host the submission reaches: the client posts a relative path on the base URL."""
        from malspark.providers.base import requested_host

        return requested_host(self._cfg.base_url, "/apiv2/tasks/create/file/")

    def submit(self, sample_path: str | Path, *, options: SubmissionOptions | None = None) -> str:
        """Submit, asking for the analysis package and guest this format needs.

        An APK handed to CAPE's default ``exe`` package detonates nothing, and
        a report of nothing is indistinguishable from a benign sample. The
        package comes from ``package_by_format`` (the sample's detected file
        type, then the ``"*"`` fallback) and the platform from the inferred
        one, only when CAPE has a name for it. Neither is guessed: an
        unconfigured format leaves both unset, which is CAPE deciding for
        itself exactly as it did before.

        Launch arguments (``options.launch_arguments``) are sent as CAPE's
        ``arguments`` option, which its analysis packages hand the started
        process (CAPE's package documentation: ``exe`` passes them to the
        initial process, ``dll`` to the DLL through its command line).
        """
        from malspark.providers.sandbox.formats import detect_sample_format, option_for_format

        file_type, platform = detect_sample_format(sample_path)
        package = option_for_format(self._cfg.package_by_format, file_type)
        extra_fields = dict(self._cfg.submit_options)
        composed: str | None = None
        arguments = options.launch_arguments if options is not None else ""
        if arguments:
            # Launch arguments ride in CAPE's own option string, beside the
            # options the deployment sends on every submission
            # (``submit_options["options"]``), which are kept.
            composed, _replaced = self._options_with_arguments(arguments)
            extra_fields.pop(_OPTIONS_FIELD, None)
        try:
            return str(
                self._get_client().submit(
                    sample_path,
                    package=package or None,
                    platform=cape_platform(platform) or None,
                    options=composed,
                    extra_fields=extra_fields,
                    mask=(lambda text: mask_submitted(text, arguments)) if arguments else None,
                )
            )
        except Exception as exc:  # noqa: BLE001 — re-raised, masked where it holds the arguments
            reraise_masked(exc, options)

    def _options_with_arguments(self, arguments: str) -> tuple[str, str]:
        """CAPE's option string carrying ``arguments``, and the deployment's arguments it replaced.

        The deployment's own option string (``submit_options["options"]``) is
        kept entry for entry, except an ``arguments=`` entry of its own, which
        the job's value replaces; the replaced value is returned so the record
        says so (``""`` where there was none).
        """
        static = str(self._cfg.submit_options.get(_OPTIONS_FIELD) or "")
        kept: list[str] = []
        replaced = ""
        for entry in static.split(_OPTION_SEPARATOR):
            if not entry.strip():
                continue
            key, _, value = entry.partition("=")
            if key.strip() == _ARGUMENTS_OPTION:
                replaced = value.strip()
                continue
            kept.append(entry)
        kept.append(f"{_ARGUMENTS_OPTION}={arguments}")
        return _OPTION_SEPARATOR.join(kept), replaced

    def launch_arguments_answer(
        self, arguments: str, *, sample_path: str | Path | None = None
    ) -> LaunchArgumentsAnswer:
        """Honoured as CAPE's ``arguments`` option, unless the value cannot be carried or read.

        A package documented to read the option (:data:`_ARGUMENT_PACKAGES`)
        is honoured as it is; any other selected package still gets them, and
        the note says whether it reads them is not documented. Not honoured
        only for a package the documentation positively states takes no such
        option (:data:`_NO_ARGUMENT_PACKAGES`). A sample whose format selects
        no package is left to CAPE.

        CAPE splits its option string at every comma before it reads a value
        (``key=value,key=value``), so a comma inside the arguments would cut
        them short and start an option of the sample's words: such a value is
        not passed. Where the deployment's own option string sets arguments
        too, the job's value replaces them, and the note says which it replaced.
        """
        from malspark.providers.submission import LaunchArgumentsAnswer

        if _OPTION_SEPARATOR in arguments:
            return LaunchArgumentsAnswer(
                honoured=False,
                note=(
                    "CAPE's option string separates its options with commas "
                    "(key=value,key=value), so launch arguments holding a comma cannot be "
                    "passed in it; the sample was detonated without them"
                ),
            )
        package = ""
        if sample_path is not None:
            from malspark.providers.sandbox.formats import detect_sample_format, option_for_format

            file_type, _platform = detect_sample_format(sample_path)
            package = option_for_format(self._cfg.package_by_format, file_type)
            if package and package in _NO_ARGUMENT_PACKAGES:
                return LaunchArgumentsAnswer(
                    honoured=False,
                    note=(
                        f"the CAPE package {package!r} this sample's format selects documents "
                        "no arguments option, so the sample was detonated without them"
                    ),
                )
        notes: list[str] = []
        if package and package not in _ARGUMENT_PACKAGES:
            notes.append(f"whether the package {package!r} reads it is not documented")
        _composed, replaced = self._options_with_arguments(arguments)
        if replaced:
            notes.append(
                f"they replace the arguments {replaced!r} that sandbox.cape2.submit_options "
                "sets on every submission"
            )
        if arguments != arguments.strip():
            notes.append("CAPE trims the spaces at their start and end")
        return LaunchArgumentsAnswer(
            honoured=True, note="; ".join(notes), via="CAPE's 'arguments' option"
        )

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int | None = None,
        poll_interval_seconds: int | None = None,
    ) -> str:
        return str(
            self._get_client().wait_for_completion(
                task_id,
                timeout_seconds=timeout_seconds or self._cfg.timeout_seconds,
                poll_interval_seconds=poll_interval_seconds or self._cfg.poll_interval_seconds,
            )
        )

    def fetch(self, task_id: str) -> SandboxRun:
        from malspark.schemas.sandbox_report import SandboxRun

        result = self._get_client().fetch_report(task_id)
        report = required_reader(_READER).read(
            result.report, provider=self.id, task_id=str(task_id)
        )
        return SandboxRun(
            task_id=str(task_id),
            sample_sha256=result.sample_sha256,
            sample_name=result.sample_name,
            status=result.status,
            report=report,
            raw=result.report,
            error=result.error,
        )

    def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
        result = self._get_client().fetch_pcap(
            task_id, dest_dir, poll_interval_seconds=self._cfg.poll_interval_seconds
        )
        return str(result) if result is not None else None

    async def probe(self) -> ProviderProbe:
        """Ask CAPE about task 1: the cheapest call that exercises URL and token."""
        import time

        import httpx

        t0 = time.perf_counter()
        token = self._cfg.api_token.get_secret_value()
        headers = {"Authorization": f"Token {token}"} if token else {}
        url = f"{self._cfg.base_url.rstrip('/')}/apiv2/tasks/view/1/"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            return ProviderProbe(
                ok=False,
                detail=redact_url(f"{type(exc).__name__}: {exc}"),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        ok = response.status_code < 400
        detail = f"HTTP {response.status_code}"
        refusal = _probe_refusal(response) if ok else None
        if refusal is not None:
            ok, detail = False, f"{detail}: {refusal}"
        return ProviderProbe(
            ok=ok,
            detail=detail,
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def close(self) -> None:
        """Release the REST pool, if one was ever built. Never raises."""
        client, self._client = self._client, None
        if client is not None:
            with suppress(Exception):
                client.close()
        handle, self._handle = self._handle, None
        if handle is not None:
            # The shared lifecycle's close: bounded, and the child reaped when
            # its transport does not shut it down. Never raises.
            handle.close()
