load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = [
        "config.go",
        "workloadio.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/workloadio/secretfile:go_default_library",
        "//pkg/util:go_default_library",
    ],
)