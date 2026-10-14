# Build context: artifacts/agent-context. No credential/config/project is copied.
FROM docker.io/library/python@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe
COPY opencode /usr/local/bin/opencode
RUN test "$(opencode --version)" = 1.2.27 && python3 --version \
    && command -v sh && mkdir -p /sandbox/project
WORKDIR /sandbox/project
ENV XDG_CONFIG_HOME=/sandbox/.config XDG_DATA_HOME=/sandbox/.local/share XDG_CACHE_HOME=/sandbox/.cache
ENV OPENCODE_DISABLE_AUTOUPDATE=true OPENCODE_DISABLE_MODELS_FETCH=true
ENTRYPOINT ["/usr/local/bin/opencode"]
