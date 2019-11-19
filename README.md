# DB Login
Contains a Java JAAS configuration that permits the Shibboleth IdP to authenticate users from a Django users database.

# Development
To rapidly run an updated version of this project execute:
```bash
mvn clean package && scp target/nau-idp-auth-1.0-SNAPSHOT.jar idpauth01-dev:/opt/tomcat/webapps/idp/WEB-INF/lib/.
```

# Deploy
This repository contains a mvn-repo folder that is a git hosted repository.
```bash
mvn clean deploy
```
