/** 
 * @constant {number} SUCCESS_STATUS_CODE The HTTP status code for a successful request
 */
const SUCCESS_STATUS_CODE = 200;
/**
 * @constnat {string} STATUS_SAFE The status returned when no threats are detected
 */
const STATUS_SAFE = "Safe";
/**
 * @constant {string} STATUS_SUSPICIOUS The status returned when some indicators are suspicious or verification failed
 */
const STATUS_SUSPICIOUS = "Suspicious";
/**
 * @constant {string} STATUS_MALICIOUS The status returned when a definitive threat is detected
 */
const STATUS_MALICIOUS = "Malicious";
/**
 * @constant (string) AUTHENTICATION_RESULT The tag where the SPF, DKIM, DMARC results exists in
 */
const AUTHENTICATION_RESULT = "Authentication-Results";
/**
 * Builds the contextual Gmail Add-on card when a message is opened
 * Uses a caching mechanism to aviod redundant backend calls for the same message
 * @param {Object} e The event object provided by Gmail, containing message details
 * @returns {CardService.Card} The constructed analysis card or an error card
 */
function buildAddOn(e) {
  var messageId = e.gmail.messageId;
  var cache = CacheService.getUserCache();
  var cachedResult = cache.get(messageId);
  // Try to retrieve previous analysis from cache to improve latency
  if (cachedResult != null) {
    return createAnalysisCard(JSON.parse(cachedResult));
  }
  // Fetch email content of not found in cache
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(messageId);
  var authResults = message.getHeader(AUTHENTICATION_RESULT);
  var attachments = message.getAttachments();
  var attachmentData = [];
  for (var i = 0; i<attachments.length; i++){
      attachmentData.push({
        "filename": attachments[i].getName(),
        "content": Utilities.base64Encode(attachments[i].getBytes()), 
        "mimeType": attachments[i].getContentType()
    });  
  }
  var payload = {
    "subject": message.getSubject(),
    "body": message.getBody(), 
    "sender": message.getFrom(),
    "authResults": authResults,
    "attachments": attachmentData
  };
  var options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(payload),
    "headers": {
      "ngrok-skip-browser-warning": "true" 
    },
    "muteHttpExceptions": true 
  };
  try {
    var response = UrlFetchApp.fetch("https://mortally-graceful-prevent.ngrok-free.dev/analyze", options);
    var responseCode = response.getResponseCode();
    if (responseCode !== SUCCESS_STATUS_CODE) {
      throw new Error("Backend returned status code " + responseCode);
    }
    var resultText = response.getContentText();
    var result = JSON.parse(resultText);
    // Saving in cache for 30 minutes
    cache.put(messageId, resultText, 1800); 
    return createAnalysisCard(result);
  } catch (error) {
    console.error("Analysis Error: " + error.toString());
    return createErrorCard();
  }
}

/**
 * Creates the UI card that displays the security analysis results
 * @param {Object} result The analysis result object returned from the backend
 * @returns {CardService.Card} The built UI card object
 */
function createAnalysisCard(result) {
  var statusColor = "#202124"; // default is gray
  var iconUrl = "https://www.gstatic.com/images/icons/material/system/1x/info_outline_black_24dp.png";
  if (result.status === STATUS_SAFE ){
    statusColor = "#34a853"; // green
    iconUrl = "https://i.ibb.co/TD0y83KR/safe-logo.png";
  } else if (result.status === STATUS_SUSPICIOUS){
    statusColor = "#fbbc04"; // orange
    iconUrl = "https://i.ibb.co/tMbTrtG3/suspicious-logo.png";
  } else if (result.status === STATUS_MALICIOUS){
    statusColor = "#ea4335"; // red
    iconUrl = "https://i.ibb.co/hxJw9Z1P/unsafe-logo.png";
  }
  var card = CardService.newCardBuilder();
  var section = CardService.newCardSection();
  card.setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer").setSubtitle("Powered by Afek").setImageStyle(CardService.ImageStyle.SQUARE).setImageUrl("https://i.ibb.co/spvJDzM6/circled-logo.png").setImageStyle(CardService.ImageStyle.CIRCLE));
  section.addWidget(CardService.newDecoratedText()
      .setText("<font color=\"" + statusColor + "\" size=\"24\"><b>" + result.status + "</b></font>")
      .setTopLabel("Analysis Result")
      .setStartIcon(CardService.newIconImage().setIconUrl(iconUrl))
      .setWrapText(true));  
    section.addWidget(CardService.newTextParagraph().setText("<b>Score:</b> " + result.score + "% malicious"));
    section.addWidget(CardService.newDivider());
  section.addWidget(CardService.newTextParagraph().setText("<b>Summary:</b> " + result.message));

  if (result.details && result.details.length > 0) {
    section.addWidget(CardService.newTextParagraph().setText("<b>Details:</b>\n• " + result.details.join("\n• ")));
  }
  card.addSection(section);
  return card.build();
}

/**
 * Create a card to notify the user of a connection or backend failure
 * @returns {CardService.Card} The error notification card
 */
function createErrorCard() {
  var card = CardService.newCardBuilder();
  var section = CardService.newCardSection();
  card.setHeader(CardService.newCardHeader().setTitle("Connection Error"));
  section.addWidget(CardService.newDecoratedText()
    .setText("<b> Can't reach PhishEye services right now.</b>")
    .setBottomLabel("Please ensure the backend server and ngrok are running.")
    .setWrapText(true)
    .setStartIcon(CardService.newIconImage()
      .setIconUrl("https://i.ibb.co/tTxvQjPr/alert-logo.png")));

  card.addSection(section);
  return card.build();
}
/**
 * Builds the homepage card with corrected syntax and larger text.
 * @returns {CardService.Card} The homepage card.
 */
function buildHomePage() {
  var card = CardService.newCardBuilder();
  var section = CardService.newCardSection();
  
  card.setHeader(CardService.newCardHeader()
    .setTitle("Malicious Email Scorer")
    .setSubtitle("Powered by Afek")
    .setImageStyle(CardService.ImageStyle.CIRCLE)
    .setImageUrl("https://i.ibb.co/spvJDzM6/circled-logo.png"));

  section.addWidget(CardService.newDecoratedText()
    .setText("<font size=\"20\"><b>Add-on is Ready!</b></font>")
    .setBottomLabel("<font size=\"14\">Open an email from your inbox to start the security analysis.</font>")
    .setStartIcon(CardService.newIconImage().setIcon(CardService.Icon.EMAIL))
    .setWrapText(true));  

  card.addSection(section);
  return card.build();
}