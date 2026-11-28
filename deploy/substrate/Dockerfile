# Clovisor beside Agent Substrate's egress gateway (milestone 7.4): the
# node agent in Substrate identity, which serves only ext_proc, and
# agentctl, for kubectl exec; and the sandbox sink (7.5), for the DaemonSet. Built by `make substrate-image`, with
# dist/substrate, where it puts static binaries, as the context.
FROM debian:bookworm-slim
COPY node-agent agentctl sandbox-sink /usr/local/bin/
USER 65532:65532
# The node agent makes these below the volumes mounted at /run/clovisor
# and /var/lib/clovisor, whose mount points it cannot chmod.
ENV CLOVISOR_SOCKET=/run/clovisor/agent/agent.sock CLOVISOR_RUNS=/var/lib/clovisor/agent/runs
ENTRYPOINT ["/usr/local/bin/node-agent"]
