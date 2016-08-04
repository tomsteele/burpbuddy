package burp

import java.net.MalformedURLException
import java.net.URL

class BScanIssue(var issue: ScanIssue): IScanIssue {
    override fun getHttpMessages(): Array<IHttpRequestResponse> {
        val messages = mutableListOf<IHttpRequestResponse>()
        for (message in issue.http_messages) {
            messages.add(BHttpRequestResponse(message, HttpService(issue.host, issue.port, issue.protocol)))
        }
        return messages.toTypedArray()
    }

    override fun getUrl(): URL {
        try {
            return URL(issue.url)
        } catch (e: MalformedURLException) {
            throw e
        }
    }

    override fun getHttpService(): IHttpService {
        return BHttpService(HttpService(issue.host, issue.port, issue.protocol))
    }

    override fun getIssueName(): String {
        return issue.name
    }

    override fun getConfidence(): String {
        return issue.confidence
    }

    override fun getIssueBackground(): String {
        return issue.issue_background
    }

    override fun getIssueDetail(): String {
        return issue.remediation_detail
    }

    override fun getIssueType(): Int {
        return 0x8000000
    }

    override fun getRemediationBackground(): String {
        return issue.remediation_background
    }

    override fun getRemediationDetail(): String {
        return issue.remediation_detail
    }

    override fun getSeverity(): String {
        return issue.severity
    }
}