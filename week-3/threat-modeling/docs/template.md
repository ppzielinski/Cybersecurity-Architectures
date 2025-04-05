<link href="docs/Stylesheet.css" rel="stylesheet"></link>

## Praxis
&nbsp;

{tm.description}

&nbsp;

## Sequence Diagram

![](seq.png)

## Dataflow Diagram

![](dfd.png)

&nbsp;

## Dataflows
&nbsp;

Name|From|To |Data|Protocol|Port
|:----:|:----:|:---:|:----:|:--------:|:----:|
{dataflows:repeat:|{{item.name}}|{{item.source.name}}|{{item.sink.name}}|{{item.data}}|{{item.protocol}}|{{item.dstPort}}|
}

## Data Dictionary
&nbsp;

Name|Description|Classification
|:----:|:--------:|:----:|
{data:repeat:|{{item.name}}|{{item.description}}|{{item.classification.name}}|
}

&nbsp;

## Potential Threats

&nbsp;
&nbsp;

|{findings:repeat:
<details>
  <summary> {{item.target}}: {{item.description}}</summary>
  <h6> Threat ID </h6>
  <p> {{item.id}} </p>
  <h6> Targeted Element </h6>
  <p> {{item.target}} </p>
  <h6> Severity </h6>
  <p>{{item.severity}}</p>
  <h6>Example Instances</h6>
  <p>{{item.example}}</p>
  <h6>Mitigations</h6>
  <p>{{item.mitigations}}</p>
  <h6>References</h6>
  <p>{{item.references}}</p>
  &nbsp;
  &nbsp;
  &emsp;
</details>
}|
