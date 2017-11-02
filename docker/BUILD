load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//docker:docker.bzl", "docker_build")

pkg_tar(
    name = "istio_ca_tar",
    extension = "tar.gz",
    srcs = [
        "//cmd/istio_ca:istio_ca",
    ],
    mode = "0755",
    package_dir = "/usr/local/bin",
    tags = [ "manual" ],
)

docker_build(
    base = "@docker_ubuntu//:xenial",
    entrypoint = [
        "/usr/local/bin/istio_ca",
        "--self-signed-ca",
    ],
    name = "istio-ca",
    tars = [ "istio_ca_tar" ],
)

pkg_tar(
    name = "istio_ca_test_tar",
    srcs = [
        "istio_ca.crt",
        "istio_ca.key",
        "//cmd/istio_ca",
    ],
    extension = "tar.gz",
    mode = "0755",
    package_dir = "/usr/local/bin",
    tags = ["manual"],
)

pkg_tar(
    name = "node_agent_test_tar",
    srcs = [
        "app.js",
        "istio_ca.crt",
        "node_agent.crt",
        "node_agent.key",
        "setup_na.sh",
        "//cmd/node_agent",
    ],
    extension = "tar.gz",
    mode = "0755",
    package_dir = "/usr/local/bin",
    tags = ["manual"],
)

docker_build(
    name = "istio-ca-test",
    base = "@docker_ubuntu//:xenial",
    entrypoint = [
        "/usr/local/bin/istio_ca",
        "--signing-cert",
        "/usr/local/bin/istio_ca.crt",
        "--signing-key",
        "/usr/local/bin/istio_ca.key",
        "--root-cert",
        "/usr/local/bin/istio_ca.crt",
        "--grpc-hostname",
        "istio-ca",
        "--grpc-port",
        "8060",
    ],
    tars = ["istio_ca_test_tar"],
)

docker_build(
    name = "node-agent-test",
    base = "@docker_ubuntu//:xenial",
    entrypoint = [
        "/bin/bash",
        "setup_na.sh",
    ],
    tars = ["node_agent_test_tar"],
)
