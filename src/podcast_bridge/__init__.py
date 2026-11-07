"""PodCast Bridge: Expose HomePod Minis as Google Cast (Chromecast Audio) devices."""

__version__ = "0.4.1"


def patch_srptools_compat() -> None:
    """Monkey-patch srptools 2.0.0+ to restore positional argument compatibility with pyatv.

    In srptools 2.0.0, SRPClientSession.__init__ and SRPServerSession.__init__ changed
    parameters (such as 'private' and 'password_verifier') to keyword-only arguments.
    pyatv calls them positionally:
      SRPClientSession(context, private_key)
      SRPServerSession(context, verifier, private_key)
    This patch detects when arguments are passed positionally and converts them to keyword arguments.
    """
    try:
        import srptools.client
        import srptools.server

        # 1. Patch SRPClientSession
        orig_client_init = srptools.client.SRPClientSession.__init__

        def _patched_client_init(self, srp_context, *args, **kwargs):
            if args:
                kwargs.setdefault("private", args[0])
                args = args[1:]
            return orig_client_init(self, srp_context, *args, **kwargs)

        srptools.client.SRPClientSession.__init__ = _patched_client_init

        # 2. Patch SRPServerSession
        orig_server_init = srptools.server.SRPServerSession.__init__

        def _patched_server_init(self, srp_context, *args, **kwargs):
            if len(args) >= 1 and "password_verifier" not in kwargs:
                kwargs["password_verifier"] = args[0]
                args = args[1:]
            if len(args) >= 1 and "private" not in kwargs:
                kwargs["private"] = args[0]
                args = args[1:]
            return orig_server_init(self, srp_context, *args, **kwargs)

        srptools.server.SRPServerSession.__init__ = _patched_server_init
    except Exception:
        pass


patch_srptools_compat()
