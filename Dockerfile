FROM grammatech/ddisasm:latest

RUN apt-get update && apt-get install -y python3 python3-pip git

RUN pip3 install gtirb gtirb-rewriting gtirb-functions gtirb-live-register-analysis

# Install latest gtirb-capstone from GitHub
RUN pip3 install git+https://github.com/GrammaTech/gtirb-capstone.git@master

RUN useradd --uid 1000 lin

USER lin
WORKDIR /workspace
