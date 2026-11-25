# Java4Shell (CVE-2026-114938) PoC container
#
# IMPORTANT: This will only reproduce on x86-64 hosts with AVX-512 VBMI.
# Running on ARM64 (even with --platform linux/amd64 via QEMU) will NOT
# trigger the bug because QEMU does not emulate AVX-512.
#
# Build:  docker build -t java4shell .
# Run:    docker run --rm java4shell
#
# To test with the mitigation flag:
#   docker run --rm java4shell java -XX:-UseBASE64Intrinsics Base64Trigger

FROM eclipse-temurin:21-jdk-noble

WORKDIR /poc
COPY Base64Trigger.java .
RUN javac Base64Trigger.java

ENTRYPOINT ["java"]
CMD ["Base64Trigger"]
