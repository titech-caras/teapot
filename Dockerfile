FROM grammatech/ddisasm:latest

RUN apt-get update && apt-get install -y python3 python3-pip git vim nano sudo

RUN pip3 install llvmlite

RUN pip3 install gtirb gtirb-rewriting gtirb-functions

# Install latest gtirb-capstone from GitHub
RUN pip3 install git+https://github.com/GrammaTech/gtirb-capstone.git@master

RUN pip3 install gtirb-live-register-analysis

RUN pip3 install pyelftools

RUN useradd --uid 1000 lin

USER lin
WORKDIR /workspace

