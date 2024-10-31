import re
from burp import IBurpExtender, IHttpListener, IScanIssue

# Create a pattern to be used in the search, considering only when we have 11 numbers together
cpf_pattern = re.compile(r'[\b\s"\'(](\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b')

def validate_cpf(cpf):
    # First, we'll check if all the digits are the same (333333333333), if yes, it's not a valid CPF and no further validation is needed
    if cpf == cpf[0] * 11:
        return False

    # Then we'll do validate the first verifier digit, that goes after the first 9 numbers
    # To do this we need to multiply each CPF digit for the respective number from 10 to 2, sum the result and then divide it by 11 (considering only int values)
    # If the result is less than 2, then the first verifier digit should be 0
    # If not we should subtract the result from 11, resulting in the verifier digit
    sum_check = sum(int(cpf[i]) * (10 - i) for i in range(9))
    check_result = sum_check % 11
    if check_result >= 10 or check_result < 2:
        digit1 = 0
    else:
        digit1 = 11 - check_result

    # For the second check, we'll do the same, but this time adding the first verifier digit provided, adding it to the end
    # This will make that we need to multiply it from 11 to 2 this time
    sum_check = sum(int(cpf[i]) * (11 - i) for i in range(10))
    check_result = sum_check % 11
    if check_result >= 10 or check_result < 2:
        digit2 = 0
    else:
        digit2 = 11 - check_result

    # Finally, we need to check if the calculated digits match the one provided in the request
    digits = [digit1, digit2]
    return cpf[-2:] == ''.join([str(x) for x in digits])

# Search for CPF in the body, validating it with the method previously created
def getCpfList(body):
    # Find all the matches of the pattern in the body, removing duplicate values by using "set" to avoid having duplicate CPF, then converting back to a list so we can work with those values
    possible_cpf_list = list(set(cpf_pattern.findall(body)))
    # Remove punctuation and sorting the result
    return sorted([''.join([c for c in x if c.isdigit()]) for x in possible_cpf_list])

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Initial configs of the extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("PII CPF Scanner")
        callbacks.registerHttpListener(self)
        print("PII CPF Scanner was correctly installed!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Process HTTP response to be able to get the body information and check for CPFs
        if not messageIsRequest:
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            # Extract the body of the response
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)

            # Calls the function getCpfList to get all CPFs from the body message in a list format
            possible_cpf_list = getCpfList(body)
            # Create a new list with the valid CPFs, after validating then with our method
            valid_cpf = [cpf for cpf in possible_cpf_list if validate_cpf(cpf)]

            # Create an issue if a CPF is found, rating its severity and recommending a remediation
            for cpf in valid_cpf:
                print("CPF: %s" % cpf)
                http_service = messageInfo.getHttpService()
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                issue_name = "PII data detect - CPF"
                # %s is a placeholder that will be replaced by the CPF number
                issue_detail = "A PII data was found in the request - CPF: %s " % cpf
                # Considering LGPD, this is considered a High Risk finding
                severity = "High"
                confidence = "Certain"
                # Besides having different possibilities of masking the CPF data, I prefer this one since it's commonly used and easier to be validated, if needed
                remediation = "You must mask the CPF so the information will not be leaked. Masking recommendation would be showing the first three numbers and the final two (e.g. 123.***.***-10)"

                issue = CustomScanIssue(
                    http_service,
                    url,
                    [messageInfo],
                    issue_name,
                    issue_detail,
                    severity,
                    confidence,
                    remediation
                )

                self._callbacks.addScanIssue(issue)


class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence, remediation):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service