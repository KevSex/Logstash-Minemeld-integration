# Logstash/Minemeld integration

With the lack of information out there to integrate minemeld with logstash, I thought I'd write up some steps detailing this procedure including a use case for Threat Intelligence feeds.

## Prerequisites

 - [Elasticsearch](https://www.elastic.co/products/elasticsearch)
 - [Minemeld](https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld)
 - [Logstash](https://www.elastic.co/products/logstash)
 
 
 ### Logstash config
 ```
 input {
  tcp {
    port => "1516"
    tags => [ "syslog" ]
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
