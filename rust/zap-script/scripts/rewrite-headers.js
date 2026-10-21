// Sample proxy and httpsender script.
// Hook names match ZAP ProxyScript and HttpSenderScript.
// Message fields are the narrow object documented by zap-script.

function proxyRequest(msg) {
    msg.setRequestHeader("X-Script-Request", "rewritten");
    return true;
}

function proxyResponse(msg) {
    msg.setResponseHeader("X-Script-Response", "rewritten");
    return true;
}

function sendingRequest(msg, initiator, helper) {
    msg.setRequestHeader("X-Sender-Request", "rewritten");
}

function responseReceived(msg, initiator, helper) {
    msg.setResponseHeader("X-Sender-Response", "rewritten");
}
