#!/usr/bin/env python3

from pytm.pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Lambda, ExternalEntity

# header
tm = TM("I3: How does it work?")
tm.description = "Application of Reinforcement Learning Methodology to Improve Robustness of Data Breach Controls"
tm.isOrdered = True

# boundaries
home = Boundary("Home")
internet = Boundary("Internet")
aws = Boundary("AWS")
company = Boundary("Company")


# Furthermore, the content risk factors refer to the 
# content type, 
# sensitivity, 
# sentiment, and 
# personally identifiable information (PII)

h3_model = Server("H3 Model")
h3_model.inBoundary = aws

pii = ExternalEntity("AWS PII Model")
pii.inBoundary = internet

sentiment = ExternalEntity("AWS Sentiment Model")
sentiment.inBoundary = internet

topic = ExternalEntity("AWS Topic Modeling")
topic.inBoundary = internet

sensitivity = ExternalEntity("AWS Phrase Matching")
sensitivity.inBoundary = internet

ner = ExternalEntity("AWS NER Model")
ner.inBoundary = internet

# ids = ExternalEntity("IDS 2018")
# ner.inBoundary = internet

# data flow
Dataflow(h3_model, pii, "Is there PII data in the content?")
Dataflow(pii, h3_model, "return true if PII in content")
Dataflow(h3_model, sentiment, "What is the sentiment of content?")
Dataflow(sentiment, h3_model, "return positive, negative or neutral")
Dataflow(h3_model, topic, "What is the topic of the content?")
Dataflow(topic, h3_model, "return topic to match against allowed or denied")
Dataflow(h3_model, sensitivity, "Does the content have any of the blocked phrases?")
Dataflow(sensitivity, h3_model, "return true if content has blocked phrases")
Dataflow(h3_model, ner, "What are the named entities in the content?")
Dataflow(ner, h3_model, "return named entities")

# render
tm.process()