--Final Project Code

hive

add jar /usr/lib/hive/lib/hive-contrib-0.10.0-cdh4.2.0.jar;
Add jar /opt/hive/lib/hive-contrib-2.3.2.jar

--set hive.io.output.fileformat = CSVTextFile;
set hive.cli.print.header=true;
--set hive.cli.print.current.db=true;

DROP TABLE apachelog;
DROP VIEW statusgroupings;
DROP VIEW FailedHostAttempts;
DROP VIEW TotalHostAttempts;
DROP TABLE StatusAggregationsByHost;
DROP VIEW by_month;
DROP VIEW by_day;
DROP VIEW FailedRequestsTimeSeriesByMonth;
DROP VIEW SuccessfulRequestsTimeSeriesByMonth;
DROP VIEW FailedRequestsTimeSeriesByDay;
DROP VIEW SuccessfulRequestsTimeSeriesByDay;
DROP VIEW unstacked_status_codes;
DROP TABLE FailedServerRequests;

CREATE TABLE apachelog (
`host` STRING,
`identity` STRING,
`user` STRING,
`time` STRING,
`request` STRING,
`status` STRING,
`size` STRING,
`referer` STRING,
`agent` STRING)
ROW FORMAT SERDE 'org.apache.hadoop.hive.contrib.serde2.RegexSerDe'
WITH SERDEPROPERTIES ( "input.regex" = "([^ ]*) ([^ ]*) ([^ ]*) (-
|\\[[^\\]]*\\]) ([^ \"]*|\"[^\"]*\") (-|[0-9]*) (-|[0-9]*)(?: ([^
\"]*|\"[^\"]*\") ([^ \"]*|\"[^\"]*\"))?", "output.format.string" =
"%1$s %2$s %3$s %4$s %5$s %6$s %7$s %8$s %9$s" )
STORED AS TEXTFILE;

LOAD DATA LOCAL INPATH "/opt/bigdata/Analytics/Analytics_and_Incidence_Response/access*" INTO TABLE apachelog;

----------------------------
--Grouping Hosts by Status Codes: Failed Requests Versus Successful Requests--

CREATE VIEW IF NOT EXISTS statusgroupings
AS
SELECT `host`
,`identity`
,`user`
,`time`
,`request`
,`status`
,`size`
,`referer`
,`agent`
,CASE substr(status,1,1)
WHEN '1' THEN '0'
WHEN '2' THEN '0'
WHEN '3' THEN '0'
WHEN '4' THEN '1'
WHEN '5' THEN '1'
ELSE '0'
END
AS failedaccess 
FROM apachelog;

INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/ApacheLog'
SELECT * FROM statusgroupings;

--sum total failed access attempts by host
CREATE VIEW IF NOT EXISTS FailedHostAttempts AS
SELECT host, SUM(failedaccess) AS failedAttempts
FROM statusgroupings
GROUP BY host
ORDER BY failedAttempts DESC;

--count total host attempts to access
CREATE VIEW IF NOT EXISTS TotalHostAttempts AS
SELECT host, count(host) AS hostAccessAttempts
FROM statusgroupings
GROUP BY host
ORDER BY hostAccessAttempts DESC;

--top 20 proportions of failed attempts
SELECT a.host, failedAttempts, hostAccessAttempts, failedAttempts / hostAccessAttempts AS percentFailed
FROM TotalHostAttempts a
JOIN FailedHostAttempts b
ON a.host = b.host
WHERE failedAttempts / hostAccessAttempts > 0
ORDER BY percentFailed DESC
LIMIT 20;

--top 20 proportions of failed attempts where more than 20 attempts total
SELECT a.host, failedAttempts, hostAccessAttempts, failedAttempts / hostAccessAttempts AS percentFailed
FROM TotalHostAttempts a
JOIN FailedHostAttempts b
ON a.host = b.host
WHERE failedAttempts / hostAccessAttempts > 0
AND hostAccessAttempts > 20
ORDER BY percentFailed DESC
LIMIT 20;

----------------------------
--Bot Activity
SELECT agent, count(agent) AS hits
FROM apachelog
WHERE agent LIKE '%bot%'
GROUP BY agent
ORDER BY hits DESC;

SELECT agent, count(agent) AS hits, MAX(status) AS sampleStatus
FROM apachelog
WHERE agent LIKE '%bot%'
AND substr(status,1,1) IN ('4','5')
GROUP BY agent
ORDER BY hits DESC
LIMIT 20;

----------------------------
--Show Percentage of Status Type Produced by Host--

CREATE TABLE StatusAggregationsByHost AS
SELECT a.host
,hostCount
,status
,statusCount
,statusCount/hostCount * 100 AS statusScore
FROM statusByHost a
JOIN hostCount b
ON a.host = b.host;

INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/RecommenderStatusData'
SELECT host
,status
,statusScore
FROM StatusAggregationsByHost
--WHERE substr(status,1,1) IN('4','5')
ORDER BY statusScore DESC;

INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/RecommenderStatus400and500Series'
SELECT host
,hostCount
,status
,statusScore
FROM StatusAggregationsByHost
WHERE substr(status,1,1) IN('4','5')
ORDER BY statusScore DESC;

----------------------------
--Seeking Attack Fingerprints with LIKE--

--conditional SQL injection
SELECT * FROM apachelog
WHERE LOWER(request) LIKE '% like %'
OR LOWER(request) LIKE '%select %'
OR LOWER(request) LIKE '% from %'
OR LOWER(request) LIKE '% where %'
OR LOWER(request) LIKE '% if %'
OR LOWER(request) LIKE '% having %'
OR LOWER(request) LIKE '% case %'
OR LOWER(request) LIKE '% when %';

--Specific Directory and Path Traversal, Command Injection
SELECT * FROM apachelog
WHERE LOWER(request) LIKE '%usr/%'
OR LOWER(request) LIKE '%~/%'
OR LOWER(request) LIKE '%.exe%'
OR LOWER(request) LIKE '%.ini%'
OR LOWER(request) LIKE '%usr/%'
OR LOWER(request) LIKE '%etc/%'
OR LOWER(request) LIKE '%dev/%'
OR LOWER(request) LIKE '%opt/%'
OR LOWER(request) LIKE '%root/%'
OR LOWER(request) LIKE '%sys/%'
OR LOWER(request) LIKE '%boot/%'
OR LOWER(request) LIKE '%mnt/%'
OR LOWER(request) LIKE '%proc/%'
OR LOWER(request) LIKE '%sbin/%'
OR LOWER(request) LIKE '%srv/%'
OR LOWER(request) LIKE '%var/%'
OR LOWER(request) LIKE '%c:\%'
OR LOWER(request) LIKE '%..%';

--Cross Site Request Forgery
SELECT * FROM apachelog
WHERE LOWER(request) LIKE '%>alert%'
OR LOWER(request) LIKE '%vulnerable%';

--Command Injection
SELECT * FROM apachelog
WHERE LOWER(request) LIKE '%&comma%'
OR LOWER(request) LIKE '%20echo%'
OR LOWER(request) LIKE '%60id%';

--MySQL Charset Switch and MSSQL DoS
SELECT * FROM apachelog
WHERE LOWER(request) LIKE '%alter%'
AND LOWER(request) LIKE '%character%'
AND LOWER(request) LIKE '%set%';

SELECT * FROM apachelog
WHERE LOWER(request) LIKE '%waitfor%'
AND LOWER(request) LIKE '%time%';

SELECT * FROM apachelog
WHERE LOWER(request) LIKE '%goto%';

----------------------------
--Time Aggregations--
CREATE VIEW IF NOT EXISTS by_month
AS
SELECT host
,`identity`
,`user`
,`time`
,CASE substr(time,5,3) 
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END
AS month
,substr(time,9,4) AS year
,concat(substr(time,9,4)
,CASE substr(time,5,3) 
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END) AS yearmonth
,concat(CASE substr(time,5,3)
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END,substr(time,2,2)) AS monthday
,request
,status
,size
,referer
,agent
FROM apachelog;

SELECT time, month, year, monthday, yearmonth FROM by_month LIMIT 10;

--enable the creation of a time series by day over multiple years and months
CREATE VIEW by_day AS
SELECT host
,`identity`
,`user`
,`time`
,concat(year, monthday) AS yearmonthday
,request
,status
,size
,referer
,agent
FROM by_month;

SELECT * FROM by_day LIMIT 10;

--Show hosts sorted by frequency of failed calls to server by day
INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/TopHostFailedLogongsByDay'
SELECT monthday
,host
,COUNT(host) AS host_freq 
FROM by_month 
WHERE substr(status,1,1) IN('4','5')
GROUP BY monthday, host 
ORDER BY host_freq DESC
LIMIT 10;

--Show hosts sorted by frequency of successful calls to server by day
INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/TopHostSuccessfulLogongsByDay'
SELECT monthday
,host
,COUNT(host) AS host_freq 
FROM by_month 
WHERE substr(status,1,1) IN('1','2','3')
GROUP BY monthday, host 
ORDER BY host_freq DESC
LIMIT 10;

--Show hosts sorted by frequency of failed calls to server by month
INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/TopHostFailedLogonsByMonth'
SELECT yearmonth
,host
,COUNT(host) AS host_freq 
FROM by_month 
WHERE substr(status,1,1) IN('4','5')
GROUP BY yearmonth, host 
ORDER BY host_freq DESC;

--Show hosts sorted by frequency of successful calls to server by month
INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/TopHostSuccessfulLogonsByMonth'
SELECT yearmonth
,host
,COUNT(host) AS host_freq 
FROM by_month 
WHERE substr(status,1,1) IN('1','2','3')
GROUP BY yearmonth, host 
ORDER BY host_freq DESC;

--Unsuccessful server calls as a time series by year and month
Create VIEW FailedRequestsTimeSeriesByMonth AS
SELECT yearmonth
,COUNT(yearmonth) AS failedrequest_freq 
FROM by_month 
WHERE substr(status,1,1) IN('4','5')
GROUP BY yearmonth
ORDER BY yearmonth ASC;

--Successful server calls as a time series by year and month
Create VIEW SuccessfulRequestsTimeSeriesByMonth AS
SELECT yearmonth
,COUNT(yearmonth) AS successfulrequest_freq 
FROM by_month 
WHERE substr(status,1,1) IN('1','2','3')
GROUP BY yearmonth
ORDER BY yearmonth ASC;

SELECT a.yearmonth
,failedrequest_freq / successfulrequest_freq AS failratio
FROM FailedRequestsTimeSeriesByMonth a
JOIN SuccessfulRequestsTimeSeriesByMonth b
ON a.yearmonth = b.yearmonth
ORDER BY yearmonth ASC;

--Produce ratio of failed to successful queries by day, instead of month
--Unsuccessful server calls as a time series by year, month, and day
Create VIEW FailedRequestsTimeSeriesByDay AS
SELECT yearmonthday
,COUNT(yearmonthday) AS failedrequest_freq 
FROM by_day 
WHERE substr(status,1,1) IN('4','5')
GROUP BY yearmonthday
ORDER BY yearmonthday ASC;

--Successful server calls as a time series by year, month, and day
Create VIEW SuccessfulRequestsTimeSeriesByDay AS
SELECT yearmonthday
,COUNT(yearmonthday) AS successfulrequest_freq 
FROM by_day 
WHERE substr(status,1,1) IN('1','2','3')
GROUP BY yearmonthday
ORDER BY yearmonthday ASC;

--Calculate ratio of failed to successful requests by year, month, and day
INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/FailedRequestsByDay'
SELECT a.yearmonthday
,a.failedrequest_freq / b.successfulrequest_freq AS failratio
FROM FailedRequestsTimeSeriesByDay a
JOIN SuccessfulRequestsTimeSeriesByDay b
ON a.yearmonthday = b.yearmonthday
ORDER BY yearmonthday ASC;

--Unstack status codes into individual columns, create date fields, and show all other columns as well
CREATE VIEW IF NOT EXISTS unstacked_status_codes
AS
SELECT host
,identity
,user
,time
,CASE substr(time,5,3) 
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END
AS month
,substr(time,9,4) AS year
,concat(substr(time,9,4)
,CASE substr(time,5,3) 
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END) AS yearmonth
,concat(CASE substr(time,5,3)
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END,substr(time,2,2)) AS monthday
,request
,CASE status WHEN '100' THEN 1 ELSE 0 END AS 100Continue
,CASE status WHEN '101' THEN 1 ELSE 0 END AS 101SwitchingProtocols
,CASE status WHEN '102' THEN 1 ELSE 0 END AS 102Processing
,CASE status WHEN '200' THEN 1 ELSE 0 END AS 200OK
,CASE status WHEN '201' THEN 1 ELSE 0 END AS 201Created
,CASE status WHEN '202' THEN 1 ELSE 0 END AS 202Accepted
,CASE status WHEN '203' THEN 1 ELSE 0 END AS 203NonAuthoritativeInformation
,CASE status WHEN '204' THEN 1 ELSE 0 END AS 204NoContent
,CASE status WHEN '205' THEN 1 ELSE 0 END AS 205ResetContent
,CASE status WHEN '206' THEN 1 ELSE 0 END AS 206PartialContent
,CASE status WHEN '207' THEN 1 ELSE 0 END AS 207MultiStatus
,CASE status WHEN '208' THEN 1 ELSE 0 END AS 208AlreadyReported
,CASE status WHEN '226' THEN 1 ELSE 0 END AS 226IMUsed
,CASE status WHEN '300' THEN 1 ELSE 0 END AS 300MultipleChoices
,CASE status WHEN '301' THEN 1 ELSE 0 END AS 301MovedPermanently
,CASE status WHEN '302' THEN 1 ELSE 0 END AS 302Found
,CASE status WHEN '303' THEN 1 ELSE 0 END AS 303SeeOther
,CASE status WHEN '304' THEN 1 ELSE 0 END AS 304NotModified
,CASE status WHEN '305' THEN 1 ELSE 0 END AS 305UseProxy
,CASE status WHEN '306' THEN 1 ELSE 0 END AS 306SwitchProxy
,CASE status WHEN '307' THEN 1 ELSE 0 END AS 307TemporaryRedirect
,CASE status WHEN '308' THEN 1 ELSE 0 END AS 308PermanentRedirect
,CASE status WHEN '400' THEN 1 ELSE 0 END AS 400BadRequest
,CASE status WHEN '401' THEN 1 ELSE 0 END AS 401Unauthorized
,CASE status WHEN '402' THEN 1 ELSE 0 END AS 402PaymentRequired
,CASE status WHEN '403' THEN 1 ELSE 0 END AS 403Forbidden
,CASE status WHEN '404' THEN 1 ELSE 0 END AS 404NotFound
,CASE status WHEN '405' THEN 1 ELSE 0 END AS 405MethodNotAllowed
,CASE status WHEN '406' THEN 1 ELSE 0 END AS 406NotAcceptable
,CASE status WHEN '407' THEN 1 ELSE 0 END AS 407ProxyAuthenticationRequired
,CASE status WHEN '408' THEN 1 ELSE 0 END AS 408RequestTimeout
,CASE status WHEN '409' THEN 1 ELSE 0 END AS 409Conflict
,CASE status WHEN '410' THEN 1 ELSE 0 END AS 410Gone
,CASE status WHEN '411' THEN 1 ELSE 0 END AS 411LengthRequired
,CASE status WHEN '412' THEN 1 ELSE 0 END AS 412PreconditionFailed
,CASE status WHEN '413' THEN 1 ELSE 0 END AS 413RequestEntityTooLarge
,CASE status WHEN '414' THEN 1 ELSE 0 END AS 414RequestUriTooLong
,CASE status WHEN '415' THEN 1 ELSE 0 END AS 415UnsupportedMediaType
,CASE status WHEN '416' THEN 1 ELSE 0 END AS 416RequestedRangeNotSatisfiable
,CASE status WHEN '417' THEN 1 ELSE 0 END AS 417ExpectationFailed
,CASE status WHEN '418' THEN 1 ELSE 0 END AS 418ImATeapot
,CASE status WHEN '420' THEN 1 ELSE 0 END AS 420EnhanceYourCalm
,CASE status WHEN '422' THEN 1 ELSE 0 END AS 422UnprocessableEntity
,CASE status WHEN '423' THEN 1 ELSE 0 END AS 423Locked
,CASE status WHEN '424' THEN 1 ELSE 0 END AS 424FailedDependency
,CASE status WHEN '424' THEN 1 ELSE 0 END AS 424MethodFailure
,CASE status WHEN '425' THEN 1 ELSE 0 END AS 425UnorderedCollection
,CASE status WHEN '426' THEN 1 ELSE 0 END AS 426UpgradeRequired
,CASE status WHEN '428' THEN 1 ELSE 0 END AS 428PreconditionRequired
,CASE status WHEN '429' THEN 1 ELSE 0 END AS 429TooManyRequests
,CASE status WHEN '431' THEN 1 ELSE 0 END AS 431RequestHeaderFieldsTooLarge
,CASE status WHEN '444' THEN 1 ELSE 0 END AS 444NoResponse
,CASE status WHEN '449' THEN 1 ELSE 0 END AS 449RetryWith
,CASE status WHEN '450' THEN 1 ELSE 0 END AS 450BlockedByWindowsParentalControls
,CASE status WHEN '451' THEN 1 ELSE 0 END AS 451UnavailableForLegalReasonsOrRedirect
,CASE status WHEN '494' THEN 1 ELSE 0 END AS 494RequestHeaderTooLarge
,CASE status WHEN '495' THEN 1 ELSE 0 END AS 495CertError
,CASE status WHEN '496' THEN 1 ELSE 0 END AS 496NoCert
,CASE status WHEN '497' THEN 1 ELSE 0 END AS 497HttpToHttps
,CASE status WHEN '499' THEN 1 ELSE 0 END AS 499ClientClosedRequest
,CASE status WHEN '500' THEN 1 ELSE 0 END AS 500InternalServerError
,CASE status WHEN '501' THEN 1 ELSE 0 END AS 501NotImplemented
,CASE status WHEN '502' THEN 1 ELSE 0 END AS 502BadGateway
,CASE status WHEN '503' THEN 1 ELSE 0 END AS 503ServiceUnavailable
,CASE status WHEN '504' THEN 1 ELSE 0 END AS 504GatewayTimeout
,CASE status WHEN '505' THEN 1 ELSE 0 END AS 505HttpVersionNotSupported
,CASE status WHEN '506' THEN 1 ELSE 0 END AS 506VariantAlsoNegotiates
,CASE status WHEN '507' THEN 1 ELSE 0 END AS 507InsufficientStorage
,CASE status WHEN '508' THEN 1 ELSE 0 END AS 508LoopDetected
,CASE status WHEN '509' THEN 1 ELSE 0 END AS 509BandwidthLimitExceeded
,CASE status WHEN '510' THEN 1 ELSE 0 END AS 510NotExtended
,CASE status WHEN '511' THEN 1 ELSE 0 END AS 511NetworkAuthenticationRequired
,CASE status WHEN '598' THEN 1 ELSE 0 END AS 598NetworkReadTimeoutError
,CASE status WHEN '599' THEN 1 ELSE 0 END AS 599NetworkConnectTimeoutError
,size
,referer
,agent
FROM apachelog;

INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/UnstackedStatusCodes'
SELECT count() 
FROM unstacked_status_codes;

--Unstacked status codes with a yearmonthday field - not aggregated - sourced from by_day view
CREATE VIEW IF NOT EXISTS unstacked_status_by_day
AS
SELECT host
,`identity`
,`user`
,`time`
,CASE substr(time,5,3) 
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END
AS month
,substr(time,9,4) AS year
,concat(substr(time,9,4)
,CASE substr(time,5,3) 
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END) AS yearmonth
,concat(CASE substr(time,5,3)
WHEN 'Jan' THEN '01'
WHEN 'Feb' THEN '02'
WHEN 'Mar' THEN '03'
WHEN 'Apr' THEN '04'
WHEN 'May' THEN '05'
WHEN 'Jun' THEN '06'
WHEN 'Jul' THEN '07'
WHEN 'Aug' THEN '08'
WHEN 'Sep' THEN '09'
WHEN 'Oct' THEN '10'
WHEN 'Nov' THEN '11'
WHEN 'Dec' THEN '12'
ELSE '00'
END,substr(time,2,2)) AS monthday
,request
,CASE status WHEN '100' THEN 1 ELSE 0 END AS 100Continue
,CASE status WHEN '101' THEN 1 ELSE 0 END AS 101SwitchingProtocols
,CASE status WHEN '102' THEN 1 ELSE 0 END AS 102Processing
,CASE status WHEN '200' THEN 1 ELSE 0 END AS 200OK
,CASE status WHEN '201' THEN 1 ELSE 0 END AS 201Created
,CASE status WHEN '202' THEN 1 ELSE 0 END AS 202Accepted
,CASE status WHEN '203' THEN 1 ELSE 0 END AS 203NonAuthoritativeInformation
,CASE status WHEN '204' THEN 1 ELSE 0 END AS 204NoContent
,CASE status WHEN '205' THEN 1 ELSE 0 END AS 205ResetContent
,CASE status WHEN '206' THEN 1 ELSE 0 END AS 206PartialContent
,CASE status WHEN '207' THEN 1 ELSE 0 END AS 207MultiStatus
,CASE status WHEN '208' THEN 1 ELSE 0 END AS 208AlreadyReported
,CASE status WHEN '226' THEN 1 ELSE 0 END AS 226IMUsed
,CASE status WHEN '300' THEN 1 ELSE 0 END AS 300MultipleChoices
,CASE status WHEN '301' THEN 1 ELSE 0 END AS 301MovedPermanently
,CASE status WHEN '302' THEN 1 ELSE 0 END AS 302Found
,CASE status WHEN '303' THEN 1 ELSE 0 END AS 303SeeOther
,CASE status WHEN '304' THEN 1 ELSE 0 END AS 304NotModified
,CASE status WHEN '305' THEN 1 ELSE 0 END AS 305UseProxy
,CASE status WHEN '306' THEN 1 ELSE 0 END AS 306SwitchProxy
,CASE status WHEN '307' THEN 1 ELSE 0 END AS 307TemporaryRedirect
,CASE status WHEN '308' THEN 1 ELSE 0 END AS 308PermanentRedirect
,CASE status WHEN '400' THEN 1 ELSE 0 END AS 400BadRequest
,CASE status WHEN '401' THEN 1 ELSE 0 END AS 401Unauthorized
,CASE status WHEN '402' THEN 1 ELSE 0 END AS 402PaymentRequired
,CASE status WHEN '403' THEN 1 ELSE 0 END AS 403Forbidden
,CASE status WHEN '404' THEN 1 ELSE 0 END AS 404NotFound
,CASE status WHEN '405' THEN 1 ELSE 0 END AS 405MethodNotAllowed
,CASE status WHEN '406' THEN 1 ELSE 0 END AS 406NotAcceptable
,CASE status WHEN '407' THEN 1 ELSE 0 END AS 407ProxyAuthenticationRequired
,CASE status WHEN '408' THEN 1 ELSE 0 END AS 408RequestTimeout
,CASE status WHEN '409' THEN 1 ELSE 0 END AS 409Conflict
,CASE status WHEN '410' THEN 1 ELSE 0 END AS 410Gone
,CASE status WHEN '411' THEN 1 ELSE 0 END AS 411LengthRequired
,CASE status WHEN '412' THEN 1 ELSE 0 END AS 412PreconditionFailed
,CASE status WHEN '413' THEN 1 ELSE 0 END AS 413RequestEntityTooLarge
,CASE status WHEN '414' THEN 1 ELSE 0 END AS 414RequestUriTooLong
,CASE status WHEN '415' THEN 1 ELSE 0 END AS 415UnsupportedMediaType
,CASE status WHEN '416' THEN 1 ELSE 0 END AS 416RequestedRangeNotSatisfiable
,CASE status WHEN '417' THEN 1 ELSE 0 END AS 417ExpectationFailed
,CASE status WHEN '418' THEN 1 ELSE 0 END AS 418ImATeapot
,CASE status WHEN '420' THEN 1 ELSE 0 END AS 420EnhanceYourCalm
,CASE status WHEN '422' THEN 1 ELSE 0 END AS 422UnprocessableEntity
,CASE status WHEN '423' THEN 1 ELSE 0 END AS 423Locked
,CASE status WHEN '424' THEN 1 ELSE 0 END AS 424FailedDependency
,CASE status WHEN '424' THEN 1 ELSE 0 END AS 424MethodFailure
,CASE status WHEN '425' THEN 1 ELSE 0 END AS 425UnorderedCollection
,CASE status WHEN '426' THEN 1 ELSE 0 END AS 426UpgradeRequired
,CASE status WHEN '428' THEN 1 ELSE 0 END AS 428PreconditionRequired
,CASE status WHEN '429' THEN 1 ELSE 0 END AS 429TooManyRequests
,CASE status WHEN '431' THEN 1 ELSE 0 END AS 431RequestHeaderFieldsTooLarge
,CASE status WHEN '444' THEN 1 ELSE 0 END AS 444NoResponse
,CASE status WHEN '449' THEN 1 ELSE 0 END AS 449RetryWith
,CASE status WHEN '450' THEN 1 ELSE 0 END AS 450BlockedByWindowsParentalControls
,CASE status WHEN '451' THEN 1 ELSE 0 END AS 451UnavailableForLegalReasonsOrRedirect
,CASE status WHEN '494' THEN 1 ELSE 0 END AS 494RequestHeaderTooLarge
,CASE status WHEN '495' THEN 1 ELSE 0 END AS 495CertError
,CASE status WHEN '496' THEN 1 ELSE 0 END AS 496NoCert
,CASE status WHEN '497' THEN 1 ELSE 0 END AS 497HttpToHttps
,CASE status WHEN '499' THEN 1 ELSE 0 END AS 499ClientClosedRequest
,CASE status WHEN '500' THEN 1 ELSE 0 END AS 500InternalServerError
,CASE status WHEN '501' THEN 1 ELSE 0 END AS 501NotImplemented
,CASE status WHEN '502' THEN 1 ELSE 0 END AS 502BadGateway
,CASE status WHEN '503' THEN 1 ELSE 0 END AS 503ServiceUnavailable
,CASE status WHEN '504' THEN 1 ELSE 0 END AS 504GatewayTimeout
,CASE status WHEN '505' THEN 1 ELSE 0 END AS 505HttpVersionNotSupported
,CASE status WHEN '506' THEN 1 ELSE 0 END AS 506VariantAlsoNegotiates
,CASE status WHEN '507' THEN 1 ELSE 0 END AS 507InsufficientStorage
,CASE status WHEN '508' THEN 1 ELSE 0 END AS 508LoopDetected
,CASE status WHEN '509' THEN 1 ELSE 0 END AS 509BandwidthLimitExceeded
,CASE status WHEN '510' THEN 1 ELSE 0 END AS 510NotExtended
,CASE status WHEN '511' THEN 1 ELSE 0 END AS 511NetworkAuthenticationRequired
,CASE status WHEN '598' THEN 1 ELSE 0 END AS 598NetworkReadTimeoutError
,CASE status WHEN '599' THEN 1 ELSE 0 END AS 599NetworkConnectTimeoutError
,size
,referer
,agent
FROM by_day;


--Create yearmonthday field with a concatenation of year and monthday fields
CREATE VIEW summed_status_by_day AS
SELECT 
year
,monthday
,concat(year, monthday) AS yearmonthday
,SUM(100Continue)  AS 100Continue
,SUM(101SwitchingProtocols)  AS 101SwitchingProtocols
,SUM(102Processing)  AS 102Processing
,SUM(200OK)  AS 200OK
,SUM(201Created)  AS 201Created
,SUM(202Accepted)  AS 202Accepted
,SUM(203NonAuthoritativeInformation)  AS 203NonAuthoritativeInformation
,SUM(204NoContent)  AS 204NoContent
,SUM(205ResetContent)  AS 205ResetContent
,SUM(206PartialContent)  AS 206PartialContent
,SUM(207MultiStatus)  AS 207MultiStatus
,SUM(208AlreadyReported)  AS 208AlreadyReported
,SUM(226IMUsed)  AS 226IMUsed
,SUM(300MultipleChoices)  AS 300MultipleChoices
,SUM(301MovedPermanently)  AS 301MovedPermanently
,SUM(302Found)  AS 302Found
,SUM(303SeeOther)  AS 303SeeOther
,SUM(304NotModified)  AS 304NotModified
,SUM(305UseProxy)  AS 305UseProxy
,SUM(306SwitchProxy)  AS 306SwitchProxy
,SUM(307TemporaryRedirect)  AS 307TemporaryRedirect
,SUM(308PermanentRedirect)  AS 308PermanentRedirect
,SUM(400BadRequest)  AS 400BadRequest
,SUM(401Unauthorized)  AS 401Unauthorized
,SUM(402PaymentRequired)  AS 402PaymentRequired
,SUM(403Forbidden)  AS 403Forbidden
,SUM(404NotFound)  AS 404NotFound
,SUM(405MethodNotAllowed)  AS 405MethodNotAllowed
,SUM(406NotAcceptable)  AS 406NotAcceptable
,SUM(407ProxyAuthenticationRequired)  AS 407ProxyAuthenticationRequired
,SUM(408RequestTimeout)  AS 408RequestTimeout
,SUM(409Conflict)  AS 409Conflict
,SUM(410Gone)  AS 410Gone
,SUM(411LengthRequired)  AS 411LengthRequired
,SUM(412PreconditionFailed)  AS 412PreconditionFailed
,SUM(413RequestEntityTooLarge)  AS 413RequestEntityTooLarge
,SUM(414RequestUriTooLong)  AS 414RequestUriTooLong
,SUM(415UnsupportedMediaType)  AS 415UnsupportedMediaType
,SUM(416RequestedRangeNotSatisfiable)  AS 416RequestedRangeNotSatisfiable
,SUM(417ExpectationFailed)  AS 417ExpectationFailed
,SUM(418ImATeapot)  AS 418ImATeapot
,SUM(420EnhanceYourCalm)  AS 420EnhanceYourCalm
,SUM(422UnprocessableEntity)  AS 422UnprocessableEntity
,SUM(423Locked)  AS 423Locked
,SUM(424FailedDependency)  AS 424FailedDependency
,SUM(424MethodFailure)  AS 424MethodFailure
,SUM(425UnorderedCollection)  AS 425UnorderedCollection
,SUM(426UpgradeRequired)  AS 426UpgradeRequired
,SUM(428PreconditionRequired)  AS 428PreconditionRequired
,SUM(429TooManyRequests)  AS 429TooManyRequests
,SUM(431RequestHeaderFieldsTooLarge)  AS 431RequestHeaderFieldsTooLarge
,SUM(444NoResponse)  AS 444NoResponse
,SUM(449RetryWith)  AS 449RetryWith
,SUM(450BlockedByWindowsParentalControls)  AS 450BlockedByWindowsParentalControls
,SUM(451UnavailableForLegalReasonsOrRedirect)  AS 451UnavailableForLegalReasonsOrRedirect
,SUM(494RequestHeaderTooLarge)  AS 494RequestHeaderTooLarge
,SUM(495CertError)  AS 495CertError
,SUM(496NoCert)  AS 496NoCert
,SUM(497HttpToHttps)  AS 497HttpToHttps
,SUM(499ClientClosedRequest)  AS 499ClientClosedRequest
,SUM(500InternalServerError)  AS 500InternalServerError
,SUM(501NotImplemented)  AS 501NotImplemented
,SUM(502BadGateway)  AS 502BadGateway
,SUM(503ServiceUnavailable)  AS 503ServiceUnavailable
,SUM(504GatewayTimeout)  AS 504GatewayTimeout
,SUM(505HttpVersionNotSupported)  AS 505HttpVersionNotSupported
,SUM(506VariantAlsoNegotiates)  AS 506VariantAlsoNegotiates
,SUM(507InsufficientStorage)  AS 507InsufficientStorage
,SUM(508LoopDetected)  AS 508LoopDetected
,SUM(509BandwidthLimitExceeded)  AS 509BandwidthLimitExceeded
,SUM(510NotExtended)  AS 510NotExtended
,SUM(511NetworkAuthenticationRequired)  AS 511NetworkAuthenticationRequired
,SUM(598NetworkReadTimeoutError)  AS 598NetworkReadTimeoutError
,SUM(599NetworkConnectTimeoutError)  AS 599NetworkConnectTimeoutError
FROM unstacked_status_by_day
GROUP BY year, monthday
ORDER BY year, monthday ASC;



--Create Failed Server Reqeusts Table for Potential External Analysis--
CREATE TABLE IF NOT EXISTS FailedServerRequests ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n' AS
SELECT 
`host`
,identity
,`user`
,time
,size
,referer
,status
,agent
FROM apachelog
WHERE substr(status,1,1) IN('4','5');

INSERT OVERWRITE LOCAL DIRECTORY '/mnt/hgfs/BigDataAnalytics/FinalProject/RequestsFailed'
SELECT * FROM FailedServerRequests;

SELECT * FROM FailedServerRequests LIMIT 20;

















