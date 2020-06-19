package main

import (
	"encoding/binary"
	evs "github.com/cybermaggedon/evs-golang-api"
	pb "github.com/cybermaggedon/evs-golang-api/protos"
	ind "github.com/cybermaggedon/indicators"
	"github.com/prometheus/client_golang/prometheus"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

type DetectorConfig struct {
	*evs.Config
	IndicatorFile string
}

func NewDetectorConfig() *DetectorConfig {

	var file string
	var ok bool
	file, ok = os.LookupEnv("INDICATORS")
	if !ok {
		file = "indicators.json"
	}

	return &DetectorConfig{
		Config:        evs.NewConfig("evs-detector", "geo"),
		IndicatorFile: file,
	}

}

// Detector analytic
type Detector struct {
	*DetectorConfig

	// Embed EventAnalytic framework
	*evs.EventSubscriber
	*evs.EventProducer
	evs.Interruptible

	// An FSM collection, powers the token scanning
	fsmc *ind.FsmCollection

	// Indicator last update time
	lastIndicatorUpdate time.Time

	// Channel to communicate new FSMs from the Reloader thread to the
	// main handler
	ch chan *ind.FsmCollection

	indicator_count prometheus.Gauge
	hits            prometheus.Histogram
	category_hits   *prometheus.CounterVec
	type_hits       *prometheus.CounterVec
}

// Converts a 32-bit int to an IP address
func int32ToIp(ipLong uint32) net.IP {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, ipLong)
	return net.IP(ipByte)
}

// Converts a byte array to an IP address. This is for IPv6 addresses.
func bytesToIp(b []byte) net.IP {
	return net.IP(b)
}

func GetTokens(ev *pb.Event) *[]ind.Token {

	tk := []ind.Token{}

	GetAddresses(ev, &tk)
	GetDns(ev, &tk)
	GetUrl(ev, &tk)
	GetEmail(ev, &tk)

	return &tk

}

func GetDns(ev *pb.Event, tk *[]ind.Token) {
	dns := ev.GetDnsMessage()
	if dns == nil {
		return
	}
	for _, v := range dns.Query {
		*tk = append(*tk, ind.Token{"hostname", v.Name})
	}
	for _, v := range dns.Answer {
		*tk = append(*tk, ind.Token{"hostname", v.Name})
	}
}

func GetUrl(ev *pb.Event, tk *[]ind.Token) {
	if ev.Url != "" {
		*tk = append(*tk, ind.Token{"url", ev.Url})
	}
}

func GetEmail(ev *pb.Event, tk *[]ind.Token) {
	smtp_data := ev.GetSmtpData()
	if smtp_data == nil {
		return
	}

	if smtp_data.From != "" {
		*tk = append(*tk,
			ind.Token{"email", ev.GetSmtpData().From})
	}
	for _, v := range smtp_data.To {
		*tk = append(*tk, ind.Token{"email", v})
	}
}

func GetAddresses(ev *pb.Event, tk *[]ind.Token) {

	for _, addr := range ev.Src {
		if addr.Protocol == pb.Protocol_ipv4 {
			ip := int32ToIp(addr.Address.GetIpv4()).String()
			*tk = append(*tk, ind.Token{"ipv4", ip})
			*tk = append(*tk, ind.Token{"ipv4.src", ip})
		}
		if addr.Protocol == pb.Protocol_ipv6 {
			ip := bytesToIp(addr.Address.GetIpv6()).String()
			*tk = append(*tk, ind.Token{"ipv6", ip})
			*tk = append(*tk, ind.Token{"ipv6.src", ip})
		}
		if addr.Protocol == pb.Protocol_tcp {
			port := strconv.Itoa(int(addr.Address.GetPort()))
			*tk = append(*tk, ind.Token{"tcp", port})
			*tk = append(*tk, ind.Token{"tcp.src", port})
		}
		if addr.Protocol == pb.Protocol_udp {
			port := strconv.Itoa(int(addr.Address.GetPort()))
			*tk = append(*tk, ind.Token{"udp", port})
			*tk = append(*tk, ind.Token{"udp.src", port})
		}
	}

	for _, addr := range ev.Dest {
		if addr.Protocol == pb.Protocol_ipv4 {
			ip := int32ToIp(addr.Address.GetIpv4()).String()
			*tk = append(*tk, ind.Token{"ipv4", ip})
			*tk = append(*tk, ind.Token{"ipv4.dest", ip})
		}
		if addr.Protocol == pb.Protocol_ipv6 {
			ip := bytesToIp(addr.Address.GetIpv6()).String()
			*tk = append(*tk, ind.Token{"ipv6", ip})
			*tk = append(*tk, ind.Token{"ipv6.dest", ip})
		}
		if addr.Protocol == pb.Protocol_tcp {
			port := strconv.Itoa(int(addr.Address.GetPort()))
			*tk = append(*tk, ind.Token{"tcp", port})
			*tk = append(*tk, ind.Token{"tcp.dest", port})
		}
		if addr.Protocol == pb.Protocol_udp {
			port := strconv.Itoa(int(addr.Address.GetPort()))
			*tk = append(*tk, ind.Token{"udp", port})
			*tk = append(*tk, ind.Token{"udp.dest", port})
		}
	}

}

func (d *Detector) LoadIndicators() (*ind.FsmCollection, error) {

	stat, err := os.Stat(d.IndicatorFile)
	if err != nil {
		return nil, err
	}

	d.lastIndicatorUpdate = stat.ModTime()

	ii, err := ind.LoadIndicatorsFromFile(d.IndicatorFile)
	if err != nil {
		return nil, err
	}

	fsmc := ind.CreateFsmCollection(ii)

	d.indicator_count.Set(float64(len(ii.Indicators)))

	log.Printf("%d FSMs created", len(fsmc.Fsms))

	return fsmc, nil

}

func (d *Detector) Reloader() {

	for {

		time.Sleep(5 * time.Second)

		stat, err := os.Stat(d.IndicatorFile)
		if err != nil {
			log.Printf("Stat error on indicator file!: %v", err)
			continue
		}

		// If indicator file is unchanged, go back and wait
		if stat.ModTime() == d.lastIndicatorUpdate {
			continue
		}

		log.Print("Loading indicators...")
		fsmc, err := d.LoadIndicators()
		if err != nil {
			log.Printf("Error loading indicators: %v", err)
			return
		}
		log.Print("Indicators loaded.")

		// Pass indicators to chan
		d.ch <- fsmc

	}

}

// Event handler
func (d *Detector) Event(ev *pb.Event, properties map[string]string) error {

	select {
	case fsmc := <-d.ch:
		d.fsmc = fsmc
		log.Print("Using new indicators.")
	default:
	}

	tokens := GetTokens(ev)

	d.fsmc.Reset()
	for _, v := range *tokens {
		d.fsmc.Update(v)
	}
	d.fsmc.Update(ind.Token{"end", ""})
	hits := d.fsmc.GetHits()

	d.hits.Observe(float64(len(hits)))

	for _, v := range hits {
		i := &pb.Indicator{}
		i.Id = v.Id
		i.Type = v.Descriptor.Type
		i.Value = v.Descriptor.Value
		i.Category = v.Descriptor.Category
		i.Source = v.Descriptor.Source
		i.Author = v.Descriptor.Author
		i.Description = v.Descriptor.Description
		i.Probability = v.Descriptor.Probability
		ev.Indicators = append(ev.Indicators, i)

		d.category_hits.With(prometheus.Labels{
			"category": i.Category,
		}).Inc()
		d.type_hits.With(prometheus.Labels{
			"type": i.Type,
		}).Inc()

	}

	d.Output(ev, properties)

	return nil

}

func NewDetector(dc *DetectorConfig) *Detector {

	d := &Detector{}

	d.DetectorConfig = dc

	var err error
	d.EventSubscriber, err = evs.NewEventSubscriber(d.Name, d.Input, d)
	if err != nil {
		log.Fatal(err)
	}

	d.EventProducer, err = evs.NewEventProducer(d.Name, d.Outputs)
	if err != nil {
		log.Fatal(err)
	}

	d.RegisterStop(d)

	d.ch = make(chan *ind.FsmCollection)

	d.indicator_count = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "indicator_count",
			Help: "Number of indicators",
		})
	d.hits = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "hits",
			Help: "Number of hits on an event",
			Buckets: []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
				12, 15, 20, 25, 50},
		})
	d.category_hits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hits_on_category",
			Help: "Hits by category",
		}, []string{"category"})
	d.type_hits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hits_on_type",
			Help: "Hits by type",
		}, []string{"type"})
	prometheus.MustRegister(d.indicator_count)
	prometheus.MustRegister(d.hits)
	prometheus.MustRegister(d.category_hits)
	prometheus.MustRegister(d.type_hits)

	log.Print("Loading indicators...")
	d.fsmc, err = d.LoadIndicators()
	if err != nil {
		log.Fatal("Error loading indicators: %v", err)
	}
	log.Print("Indicators loaded.")

	go d.Reloader()

	return d

}

func main() {

	gc := NewDetectorConfig()
	g := NewDetector(gc)
	log.Print("Initialisation complete")
	g.Run()
	log.Print("Shutdown.")

}
