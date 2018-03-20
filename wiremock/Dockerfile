FROM openjdk:8-jre-alpine

ENV WM_PACKAGE wiremock

RUN mkdir -p /$WM_PACKAGE/mappings
WORKDIR /$WM_PACKAGE

ADD http://repo1.maven.org/maven2/com/github/tomakehurst/wiremock-standalone/2.14.0/wiremock-standalone-2.14.0.jar /$WM_PACKAGE
ADD wiremock-health.json /$WM_PACKAGE/mappings
ADD start.sh /$WM_PACKAGE

RUN chmod 777 /$WM_PACKAGE/start.sh

EXPOSE 8080

CMD ["/wiremock/start.sh"]