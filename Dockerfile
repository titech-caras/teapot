FROM grammatech/ddisasm:latest

RUN apt-get update && apt-get install -y python3 python3-pip
RUN python3 -m pip install gtirb gtirb-rewriting gtirb-capstone
RUN useradd --uid 1000 lin

USER lin
WORKDIR /workspace
