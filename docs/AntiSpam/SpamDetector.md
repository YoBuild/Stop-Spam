# Yohns\AntiSpam\SpamDetector

SpamDetector class for comprehensive content spam detection

Analyzes content for spam patterns, keywords, and suspicious behavior.
Uses machine learning-style scoring to determine spam likelihood.


Usage example:
```php
$detector = new SpamDetector();
$result = $detector->analyzeContent("Buy cheap viagra now!!!");
if ($result['is_spam']) {
  echo "Spam detected with score: " . $result['spam_score'];
  echo "Reasons: " . implode(', ', $result['reasons']);
}
```

## Methods

| Name | Description |
|------|-------------|
|[__construct](#spamdetector__construct)|Constructor - Initialize spam detector with configuration|
|[addProfanityWord](#spamdetectoraddprofanityword)|Add profanity word|
|[addSpamKeyword](#spamdetectoraddspamkeyword)|Add spam keyword|
|[analyzeContent](#spamdetectoranalyzecontent)|Analyze content for spam indicators|
|[cleanContent](#spamdetectorcleancontent)|Clean content by removing spam and profanity|
|[getProfanityList](#spamdetectorgetprofanitylist)|Get profanity list|
|[getSpamKeywords](#spamdetectorgetspamkeywords)|Get spam keywords|
|[getStats](#spamdetectorgetstats)|Get spam detection statistics|
|[isEnabled](#spamdetectorisenabled)|Check if spam detection is enabled|
|[removeProfanityWord](#spamdetectorremoveprofanityword)|Remove profanity word|
|[removeSpamKeyword](#spamdetectorremovespamkeyword)|Remove spam keyword|
|[shouldAutoBlock](#spamdetectorshouldautoblock)|Check if content should be auto-blocked|
|[trainWithFeedback](#spamdetectortrainwithfeedback)|Train the spam detector with user feedback|




### SpamDetector::__construct

**Description**

```php
public __construct (void)
```

Constructor - Initialize spam detector with configuration

Loads configuration settings and initializes spam keywords and profanity lists
from storage or creates default lists if none exist.

**Parameters**

`This function has no parameters.`

**Return Values**

`void`


**Throws Exceptions**


`\Exception`
> If FileStorage initialization fails

Usage example:
```php
$detector = new SpamDetector();
// Detector is now ready to analyze content
```

<hr />


### SpamDetector::addProfanityWord

**Description**

```php
public addProfanityWord (string $word)
```

Add profanity word

Adds a new word to the profanity filter list if it doesn't already exist.
Updates the storage with the new profanity list.

**Parameters**

* `(string) $word`
: Word to add to profanity filter

**Return Values**

`bool`

> True if word was added, false if it already exists

Usage example:
```php
$detector = new SpamDetector();
if ($detector->addProfanityWord('badword')) {
    echo "Profanity word added successfully";
} else {
    echo "Word already in profanity list";
}
```


<hr />


### SpamDetector::addSpamKeyword

**Description**

```php
public addSpamKeyword (string $keyword)
```

Add spam keyword

Adds a new keyword to the spam detection list if it doesn't already exist.
Updates the storage with the new keyword list.

**Parameters**

* `(string) $keyword`
: Keyword to add to spam detection list

**Return Values**

`bool`

> True if keyword was added, false if it already exists

Usage example:
```php
$detector = new SpamDetector();
if ($detector->addSpamKeyword('new spam word')) {
    echo "Keyword added successfully";
} else {
    echo "Keyword already exists";
}
```


<hr />


### SpamDetector::analyzeContent

**Description**

```php
public analyzeContent (string $content)
```

Analyze content for spam indicators

Performs comprehensive analysis including keyword detection, profanity check,
link counting, capital letter analysis, and pattern recognition.
Returns a detailed analysis with spam score and reasons.

**Parameters**

* `(string) $content`
: Content to analyze for spam

**Return Values**

`array`

> Analysis result with 'is_spam', 'spam_score', 'reasons', 'severity' keys

Usage example:
```php
$detector = new SpamDetector();
$result = $detector->analyzeContent("CLICK HERE FOR FREE MONEY!!!");

if ($result['is_spam']) {
    echo "Spam detected! Score: " . $result['spam_score'];
    echo "Severity: " . $result['severity'];
    foreach ($result['reasons'] as $reason) {
        echo "- " . $reason . "\n";
    }
}
```


<hr />


### SpamDetector::cleanContent

**Description**

```php
public cleanContent (string $content)
```

Clean content by removing spam and profanity

Sanitizes content by replacing profanity with asterisks, reducing
excessive punctuation, and normalizing repeated characters and whitespace.

**Parameters**

* `(string) $content`
: Content to clean and sanitize

**Return Values**

`string`

> Cleaned content with profanity and spam patterns removed

Usage example:
```php
$detector = new SpamDetector();
$cleaned = $detector->cleanContent("This is damn stupid!!!! content");
echo $cleaned; // Outputs: "This is **** stupid!!! content"
```


<hr />


### SpamDetector::getProfanityList

**Description**

```php
public getProfanityList (void)
```

Get profanity list

Returns the current list of profanity words used for content filtering.
This includes both default words and any custom additions.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Array of profanity words

Usage example:
```php
$detector = new SpamDetector();
$profanity = $detector->getProfanityList();
echo "Total profanity words: " . count($profanity);
// Note: Be careful when displaying profanity words
```


<hr />


### SpamDetector::getSpamKeywords

**Description**

```php
public getSpamKeywords (void)
```

Get spam keywords

Returns the current list of spam keywords used for detection.
This includes both default keywords and any custom additions.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Array of spam keywords

Usage example:
```php
$detector = new SpamDetector();
$keywords = $detector->getSpamKeywords();
echo "Total keywords: " . count($keywords);
foreach ($keywords as $keyword) {
    echo "- " . $keyword . "\n";
}
```


<hr />


### SpamDetector::getStats

**Description**

```php
public getStats (void)
```

Get spam detection statistics

Returns comprehensive statistics about spam detection performance
including total detections, severity breakdown, top reasons, and averages.

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> Statistics array with detection counts, severity breakdown, and analysis data

Usage example:
```php
$detector = new SpamDetector();
$stats = $detector->getStats();
echo "Total detections: " . $stats['total_detections'];
echo "Average spam score: " . $stats['average_spam_score'];
echo "Recent detections (24h): " . $stats['recent_detections'];
print_r($stats['severity_breakdown']);
print_r($stats['top_reasons']);
```


<hr />


### SpamDetector::isEnabled

**Description**

```php
public isEnabled (void)
```

Check if spam detection is enabled

Returns the current enabled status of the spam detection system
based on configuration settings.

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`

> True if spam detection is enabled, false otherwise

Usage example:
```php
$detector = new SpamDetector();
if ($detector->isEnabled()) {
    $result = $detector->analyzeContent($userInput);
    // Process spam detection results
} else {
    // Spam detection is disabled, skip analysis
}
```


<hr />


### SpamDetector::removeProfanityWord

**Description**

```php
public removeProfanityWord (string $word)
```

Remove profanity word

Removes a word from the profanity filter list if it exists.
Updates the storage with the modified profanity list.

**Parameters**

* `(string) $word`
: Word to remove from profanity filter

**Return Values**

`bool`

> True if word was removed, false if it doesn't exist

Usage example:
```php
$detector = new SpamDetector();
if ($detector->removeProfanityWord('oldword')) {
    echo "Profanity word removed successfully";
} else {
    echo "Word not found in profanity list";
}
```


<hr />


### SpamDetector::removeSpamKeyword

**Description**

```php
public removeSpamKeyword (string $keyword)
```

Remove spam keyword

Removes a keyword from the spam detection list if it exists.
Updates the storage with the modified keyword list.

**Parameters**

* `(string) $keyword`
: Keyword to remove from spam detection list

**Return Values**

`bool`

> True if keyword was removed, false if it doesn't exist

Usage example:
```php
$detector = new SpamDetector();
if ($detector->removeSpamKeyword('old keyword')) {
    echo "Keyword removed successfully";
} else {
    echo "Keyword not found";
}
```


<hr />


### SpamDetector::shouldAutoBlock

**Description**

```php
public shouldAutoBlock (string $content)
```

Check if content should be auto-blocked

Determines if content should be automatically blocked based on
spam analysis. Content is auto-blocked if spam score is 0.8 or higher.

**Parameters**

* `(string) $content`
: Content to check for auto-blocking

**Return Values**

`bool`

> True if content should be auto-blocked, false otherwise

Usage example:
```php
$detector = new SpamDetector();
if ($detector->shouldAutoBlock("Buy cheap viagra now!!!")) {
    // Block this content automatically
    die("Content blocked for spam");
}
```


<hr />


### SpamDetector::trainWithFeedback

**Description**

```php
public trainWithFeedback (string $content, bool $isSpam)
```

Train the spam detector with user feedback

Collects user feedback about whether content is spam or legitimate
to improve future detection accuracy. Stores training data for analysis.

**Parameters**

* `(string) $content`
: Content to provide feedback on
* `(bool) $isSpam`
: True if content is spam, false if legitimate

**Return Values**

`void`

>

Usage example:
```php
$detector = new SpamDetector();

// User reports content as spam
$detector->trainWithFeedback($suspiciousContent, true);

// User reports content as legitimate (false positive)
$detector->trainWithFeedback($falsePositiveContent, false);

echo "Feedback recorded for machine learning improvement";
```


<hr />
