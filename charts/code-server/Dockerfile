FROM codercom/code-server:4.96.4

USER root

# Install JDK21
RUN  echo "deb [arch=amd64] https://some.repository.url focal main" | sudo tee /etc/apt/sources.list.d/adoptium.list > /dev/null

RUN apt update && apt-get install -y wget apt-transport-https gpg unzip

RUN wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public | gpg --dearmor | tee /etc/apt/trusted.gpg.d/adoptium.gpg > /dev/null

RUN echo "deb https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" | tee /etc/apt/sources.list.d/adoptium.list

RUN apt update && apt-get install -y temurin-21-jdk -y 


COPY extensions /home/coder/extensions

# Install gradle
RUN unzip -d /opt/gradle extensions/gradle-8.8-bin.zip

# Install k8s tools NEED ClusterRole API access
#COPY k8s-tools /usr/local/bin

# Install copilot extensions
USER coder
RUN code-server --install-extension extensions/copilot-1.259.1336_vsixhub.com.vsix && code-server --install-extension extensions/copilot-chat-0.23.2024120602_vsixhub.com.vsix

ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
