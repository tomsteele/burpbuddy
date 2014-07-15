package burp;

import java.net.MalformedURLException;
import java.net.URL;

public class BScanIssue extends BSocketMessage implements IScanIssue {
    public String url;
    public String host;
    public int port;
    public String protocol;
    public String name;
    public int issueType;
    public String severity;
    public String confidence;
    public String issueBackground;
    public String remediationBackground;
    public String issueDetail;
    public String remediationDetail;
    public BHttpRequestResponse[] requestResponses;
    public boolean inScope;

    /**
     * This method returns the URL for which the issue was generated.
     *
     * @return The URL for which the issue was generated.
     */
    public java.net.URL getUrl() {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    /**
     * This method returns the name of the issue type.
     *
     * @return The name of the issue type (e.g. "SQL injection").
     */
    public String getIssueName() {
        return name;
    }

    /**
     * This method returns a numeric identifier of the issue type. See the Burp
     * Scanner help documentation for a listing of all the issue types.
     *
     * @return A numeric identifier of the issue type.
     */
    public int getIssueType() {
        return issueType;
    }

    /**
     * This method returns the issue severity level.
     *
     * @return The issue severity level. Expected values are "High", "Medium",
     * "Low", "Information" or "False positive".
     *
     */
    public String getSeverity() {
        return severity;
    }

    /**
     * This method returns the issue confidence level.
     *
     * @return The issue confidence level. Expected values are "Certain", "Firm"
     * or "Tentative".
     */
    public String getConfidence() {
        return confidence;
    }

    /**
     * This method returns a background description for this type of issue.
     *
     * @return A background description for this type of issue, or
     * <code>null</code> if none applies.
     */
    public String getIssueBackground() {
        return issueBackground;
    }

    /**
     * This method returns a background description of the remediation for this
     * type of issue.
     *
     * @return A background description of the remediation for this type of
     * issue, or
     * <code>null</code> if none applies.
     */
    public String getRemediationBackground() {
        return remediationBackground;
    }

    /**
     * This method returns detailed information about this specific instance of
     * the issue.
     *
     * @return Detailed information about this specific instance of the issue,
     * or
     * <code>null</code> if none applies.
     */
    public String getIssueDetail() {
        return issueDetail;
    }

    /**
     * This method returns detailed information about the remediation for this
     * specific instance of the issue.
     *
     * @return Detailed information about the remediation for this specific
     * instance of the issue, or
     * <code>null</code> if none applies.
     */
    public String getRemediationDetail() {
        return remediationDetail;
    }

    /**
     * This method returns the HTTP messages on the basis of which the issue was
     * generated.
     *
     * @return The HTTP messages on the basis of which the issue was generated.
     * <b>Note:</b> The items in this array should be instances of
     * <code>IHttpRequestResponseWithMarkers</code> if applicable, so that
     * details of the relevant portions of the request and response messages are
     * available.
     */

    public IHttpRequestResponse[] getHttpMessages() {
        return requestResponses;
    }

    /**
     * This method returns the HTTP service for which the issue was generated.
     *
     * @return The HTTP service for which the issue was generated.
     */
    public IHttpService getHttpService() {
        return new IHttpService() {
            @Override
            public String getHost() {
                return host;
            }

            @Override
            public int getPort() {
                return port;
            }

            @Override
            public String getProtocol() {
                return protocol;
            }
        };
    }
}
