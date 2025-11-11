package co.enyoi.authentication.util;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;

public class RequestIdUtil {

    private static final String REQUEST_ID_MDC_KEY = "requestId";

    /**
     * Get the request ID from MDC (Mapped Diagnostic Context)
     * @return the request ID or null if not found
     */
    public static String getRequestId() {
        return MDC.get(REQUEST_ID_MDC_KEY);
    }

    /**
     * Get the request ID from HttpServletRequest attribute
     * @param request the HTTP request
     * @return the request ID or null if not found
     */
    public static String getRequestId(HttpServletRequest request) {
        Object requestId = request.getAttribute(REQUEST_ID_MDC_KEY);
        return requestId != null ? requestId.toString() : null;
    }
}
