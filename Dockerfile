
FROM fedora:32

COPY evs-detector /usr/local/bin/evs-detector
COPY indicators.json /usr/local/share/

ENV PULSAR_BROKER=pulsar://exchange:6650
ENV METRICS_PORT=8088
ENV INDICATORS=/usr/local/share/indicators.json
EXPOSE 8088

CMD /usr/local/bin/evs-detector

