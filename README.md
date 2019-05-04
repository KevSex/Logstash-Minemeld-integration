# Logstash/Minemeld integration

With the lack of information out there to integrate minemeld with logstash, I thought I'd write up some steps detailing this procedure including a use case for Threat Intelligence feeds.

## Prerequisites

 - [Elasticsearch](https://www.elastic.co/products/elasticsearch)
 - [Minemeld](https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld)
 - [Logstash](https://www.elastic.co/products/logstash)

## Logstash Configuration

To start, we need to prepare Logstash to ingest the data that it will receive from minemeld. We do this using a tcp input. There is some filters we apply to parse the data received and then output into Elasticsearch.
 
### Logstash config
 ```
 input {
  tcp {
    port => "1516"
  }
}

filter {

  if "@origin" in [message] {
    mutate {
      add_tag => "minemeld"
    }
    json {
      source => "message"
    }

    fingerprint {
        source => "@indicator"
        target => "[@metadata][fingerprint]"
        method => "MURMUR3"
    }

    dissect {
        mapping => { "@indicator" => "%{firstIP}-%{lastIP}" }
    }
  }
}

output {

  if "minemeld" in [tags] and [message] == "withdraw" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "minemeld"
      action => "delete"
      document_id => "%{[@metadata][fingerprint]}"
    }
  } else if "minemeld" in [tags] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "minemeld"
      document_id => "%{[@metadata][fingerprint]}"
    }
  }

}
```
#### Input

Using a basic [tcp input plugin](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-tcp.html), we open up a port for minemeld to send its data to.

#### Filter
Using an if statement, we're checking for `@origin` in the [message] received. Once found, it will tag the document with "minemeld" so we can later place these documents into its separate index. We're then parsing the message using the [json filter](https://www.elastic.co/guide/en/logstash/current/plugins-filters-json.html). This splits out the fields more appropriately rather than all data being within the one "message" field.

Next, we use the [fingerprint filter](https://www.elastic.co/guide/en/logstash/current/plugins-filters-fingerprint.html) which allows us to take the `@indicator` field and create a hash value based off this field. We then place this hash into a new temporary field called `[@metadata][fingerprint]` which we'll use later to output to elasticsearch.

Lastly, in the filter, we then using the [dissect plugin](https://www.elastic.co/guide/en/logstash/current/plugins-filters-dissect.html) which allows us to pull out the `firstIP` and `lastIP` from the `@indicator` field. This plays a part later when using the minemeld index to query IP addresses.

#### Output

For the output, we first need to look at how indicators from minemeld are maintained. I can't find any official documentation on how events are removed but [this post](https://live.paloaltonetworks.com/t5/MineMeld-Discussions/Withdraw-mesage-source/m-p/118969/highlight/true#M438) from the community forum explains it well.
We therefore use an if statement to check if the [message] value is `withdraw`. If so, we pass the `delete` action when outputting to elasticsearch.

When logstash sends an event to elasticsearch, a document_id is randomly generated. In order to keep track of documents so we can remove them when a `withdraw` message arrives, we use the fingerprint field that we set in the filter (`[@metadata][fingerprint]`)

## Elasticsearch Configuration

Now that we have Logstash set up to listen for indicators arriving from minemeld and passing the data off into Elasticsearch, we want elasticsearch to properly map the fields, e.g. IP address is marked as an IP address as opposed to a string.
To achieve this, we create a template for minemeld.

Run the following command:

```
curl -X PUT "localhost:9200/_template/minemeld" -H 'Content-Type: application/json' -d'
{
  "index_patterns": "minemeld",
  "settings": {
      "index" : {
        "mapping" : {
          "total_fields" : {
            "limit" : "10000"
          }
        },
        "refresh_interval" : "5s",
        "number_of_routing_shards" : "30",
        "number_of_shards" : "1",
	"codec": "best_compression"
      }
  },
  "mappings": {
    "doc": {
      "properties": {
		"firstIP" : { "type" : "ip" }, 
		"lastIP": { "type" : "ip" },
		"first_seen": { "type" : "date" },
		"last_seen": { "type" : "date" },
		"@timestamp": { "type" : "date" },
		"type": { "type" : "keyword" },
		"port": { "type" : "integer" },
		"message": { "type" : "keyword" },
		"confidence": { "type" : "integer" },
		"@origin": { "type" : "keyword" },
		"share_level": { "type" : "keyword" },
		"tags": { "type" : "keyword" },
		"host": { "type" : "keyword" },
		"syslog_severity_code": { "type" : "integer" },
		"syslog_severity": { "type" : "keyword" },
		"logstash_output_node": { "type" : "keyword" },
		"syslog_facility": { "type" : "keyword" },
		"dshield_email": { "type" : "keyword" },
		"dshield_name": { "type" : "keyword" },
		"dshield_country": { "type" : "keyword" },
		"dshield_nattacks": { "type" : "keyword" },
		"dshield_email": { "type" : "keyword" }
      }
    }
  }
}
'
```

Alternatively, you can download the minemeld template file from this repo and apply it like so:

```
curl -XPUT 'http://localhost:9200/_template/minemeld' -d@minemeld.template.json
```


## Troubleshooting

 - Ensure the logstash configuration is set up prior to configuring minemeld as when you restart minemeld to apply the logstash output, it will bulk send all the events. If you're logstash tcp input is not configured, you'll miss these events.
