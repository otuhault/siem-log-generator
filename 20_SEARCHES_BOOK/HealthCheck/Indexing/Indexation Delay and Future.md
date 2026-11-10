# Index Time vs Timestamp
```splunk-spl
| eval IndexTime=_indextime 
| eval idxTime=strftime(IndexTime, "%Y-%m-%d %H:%M:%S")
| eval diff=round(_indextime - _time,0)/60 . " " . "Minutes"
| table _time idxTime diff sourcetype
```
# Logs in future
```splunk-spl
| tstats count where index IN (a*,b*,c*,d*,e*,f*,g*,h*,i*,j*,k*,l*,m*,n*,o*,p*,q*,r*,s*,t*,u*,v*,w*,x*,y*,z*) earliest=+30min@m latest=2147483647 GROUPBY sourcetype source host 
| join type=left sourcetype 
    [| metadata type=sourcetypes index=* 
    | convert ctime(*Time)] 
| stats values(host) AS Hosts values(sourcetype) AS Sourcetype values(lastTime) AS "Furthest Out Event"
```
# Missing logs from indexes
```splunk-spl
| tstats count WHERE index=* earliest=-30m latest=-20m by index
| eval period="baseline"
| append [
    | tstats count WHERE index=*)  earliest=-20m latest=-10m by index
    | eval period="current"
]
| stats values(count) as count by index, period
| xyseries index period count
| eval baseline=coalesce(baseline, 0), current=coalesce(current, 0)
| eval drop_percentage=if(baseline>0, round(((baseline-current)/baseline)*100, 2), 0)
| where drop_percentage > 90 OR (baseline > 0 AND current == 0)
| table index, baseline, current, drop_percentage
```
