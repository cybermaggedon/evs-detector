
FROM fedora:32

COPY evs-detector /usr/local/bin/evs-detector

ENV PULSAR_BROKER=pulsar://exchange
ENV METRICS_PORT=8088
EXPOSE 8088

CMD /usr/local/bin/evs-dump

