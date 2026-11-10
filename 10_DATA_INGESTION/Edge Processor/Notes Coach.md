Edge Processor Pipelines expressed in SPL2 are the actual instructions to refine the data.
https://console.scs.splunk.com/awesomeco

# SPL2
## Building Blocks of SPL2
![[Pasted image 20251107123644.png]]
- Profile
	- Set of SPL2 capabilities available for a specific runtime
- Namespace
	- Identifies the profile resources
- Workspace
	- The top organisational namespace
	- Can be private or shared
- Module / Pipeline
	- A container for SPL2 code
- Dataset
	- A collection of data being operated on in modules
- Sourcetype
	- Spacial abstracted data set for the edge processor profile.

If you share a workspace, other can use it by importing it:
```
import lu_status from /shared.teamBCG/f_dcrusher
$bcgstatus = from lu_status
```
### Activity 1
![[Pasted image 20251107124547.png]]

## Modularity
An SPL2 Module begins with the command **from**
- Has **select** variations
- Both are extremely powerful

*Example:*
Classic SPL:
```
index=web sourcetype=access
| stats sum(bytes) as size by host action
| sort host
```
SPL2:
```
from web where sourcetype=access
| stats sum(bytes) as size by host, action
| sort host
```
SQL:
```
SELECT sum(bytes) AS size, host, action
  FROM web
  WHERE sourcetype='access'
  GROUP BY host, action
  ORDER BY host
```

?SPL Commands that cannot be supported in SPL2 is aided via:

Embed classic SPL commands in SPL2
Enclose SPL expressions in `backtick`
*Classic SPL*
```
index=web | bin productId span=1d as btime | stats count(productId) as pId by categoryId
```
*SPL2 search with Search Literal*
```
$spl_w_backtick = from web | `bin productId span=1d as btime`
| stats count(productId) as productId by categoryId
```
*SPL2 search with the spl1 command*
```
$spl_w_backtick = from web | spl1 "bin productId span=1d as btime"
| stats count(productId) as productId by categoryId
```

### Compatibility Library
- import addinfo from /system/compat
- import {addinfo, tags} from /system/compat
- import * from /system/compat

## Custom Functions
Type of custom functions:
- **Scalar** functions as additional eval-compatible functions.
	- Operates on a single event in time
- **Command** functions to facilitate custom commands
	- Operates on a dataset

![[Pasted image 20251107130950.png]]

![[Pasted image 20251107131127.png]]

**Differences between SPL and SPL2**
![[Pasted image 20251107131446.png]]
![[Pasted image 20251107131535.png]]
![[Pasted image 20251107131643.png]]

## Data Types
- In SPL, all data is **any** type
- SPL2 uses a progressive typing system
	- Type checking can enforce structure if necessary
	- Known types are picked up by the UI for auto-completion
	- Can define custom data structure
- Built-in data types
	- Primitives
	- Derived
	
Working with Object Data Type
![[Pasted image 20251107132715.png]]![[Pasted image 20251107132853.png]]

![[Pasted image 20251107133340.png]]
![[Pasted image 20251107133400.png]]

# First Time Setup
**scpbridge** between SplunkCloud and EdgeProcessor.
sc_admin role inherits the **tenant.admins** SCS role.
**admin_all_object** and **edit_edge_processor** capabilities control the Manage connection menu.

Sourcetypes are equivalent of the Splunk parsing and merging phases. 
### Activity
![[Pasted image 20251107145630.png]]

# Sending Data from Edge Processor
For S2S Destination, TLS Certificates are:
- Client private key = sslPassword
- Client certificate = clientCert
- CA cert for indexers = sslRootCAPath

For HEC:
- Fixed url for SplunkCloud: `https://http-inputs.<stack_id>.splunkcloud.com:443`
- Untick Indexer Acknowledgement

Index Destination Precedence
![[Pasted image 20251107151435.png]]
### Activity
![[Pasted image 20251107152002.png]]
# Getting Data into Edge Processor
Firewall rules:
- `https://<tenant>.api.scs.splunk.com`
- `https://<tenant>.auth.scs.splunk.com`
- `https://auth.scs.splunk.com`
- `https://beam.scs.splunk.com`

Avoid mix and match sources and destinations.

Unprocessed data?
- either to drop or send to default destination.
Splunk internal logs are unprocessed
- decide where to aggregate internal logs

Installing an EP Client:
- Download and Extract
- Configure
- PhoneHome - Update

Can configure the **splunk-edge** process as a systemd service
A unit file template is provided in: home/etc/splunk-edge.service
### Activity
![[Pasted image 20251107155754.png]]

# Building Custom Pipelines
Multiple pipelines that operate on the same sourcetype may result in deplicate data.
Example:
You need a specific sourcetype to be processed three different ways.
4 pipelines (operate independently) on the same sourcetype, can create duplicates.
If sourcetype doesnot match -> Unprocessed Data (Default to DROP or Default Destination)
![[Pasted image 20251107165406.png]]
When you apply the pipeline via the UI, each pipeline is currently constrained to just one destination.

A sourcetype is how EdgeProcessor currently partitions inbound data. It determines how inbound data is broken into distinct events before they go through a pipeline.

It supports the following props.conf settings:
![[Pasted image 20251107165632.png]]
### Activity
![[Pasted image 20251107170211.png]]

SPL2 Commands in EP Profile (Subject to change)
![[Pasted image 20251107172008.png]]

![[Pasted image 20251107172113.png]]

**from** Command
- EP supports a subset of its capabilities
- Loads data from any dataset
	- Optional clauses may work while previewing
Only from $source is valid for compilation.

**Dataset Literals**
- Use the JSON notation \[ {},{},{} \]
- The \[ \] represents a dataset containing a list of event objects
- Each { } represents an event object mapped with field-value pairs
- The \_raw field represents the actual event you want to mimic

**eval** Command
- Evaluates math, string, and Boolean expressions
- Calculates an expression and assigns the result into the named field
	- If the field name exists, then the result overwrites the existing value
- Can chain multiple eval expressions using a comma as a separator
- Evaluates expressions left-to-right sequentially

**Concatenation and String Templates**
- Use + to concatenate.
- Use string templates to format more complex output.
![[Pasted image 20251107173100.png]]

**fields** Command
- The assigned fields from the **eval** command emerge as indexed fields in Splunk indexers
- To prevent this, use the **fields** command
- By default, the fields **\_raw** and **\_time** are kept if one is defined.
![[Pasted image 20251107173444.png]]

**rex** Command
- Extracts field-value pairs using regex
- Substitue or remove characters with **sed** expressions
- An expression is applied to the \_raw field unless a scope is specified with the **field** argument
![[Pasted image 20251107173644.png]]

**where** Command
- Keep only events that pass a Boolean evaluation

**expand** and **flatten** Commands
![[Pasted image 20251107173815.png]]
![[Pasted image 20251107173936.png]]
![[Pasted image 20251107173957.png]]

JSON Scalar Functions.

### Use Cases
- Payload Reduction
- Mask Data: privacy, confidentiality, regulatory, etc
- Faster Search: reduce search time
- Cloud Migration: multi-forward while in transition

![[Pasted image 20251107175827.png]]
![[Pasted image 20251107180027.png]]

![[Pasted image 20251107180135.png]]

### Activity
![[Pasted image 20251107180240.png]]
