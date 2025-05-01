### Code Server 배포

- Keycloak에 등록된 User ID를 기준으로 각각의 Code-Server를 helm chart로 배포 합니다.
- values.yaml에 User ID 값을 등록합니다.
- 백엔드 개발은 Code Server Dockerfile-jdk21을 기준으로 배포
- 프론트엔드 개발은 Code Server Dockerfile-node를 기준으로 배포



