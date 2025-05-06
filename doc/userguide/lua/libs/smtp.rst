SMTP
####

.. role:: example-rule-emphasis

SMTP transaction details are exposed to Lua scripts with the
``suricata.smtp`` library, for example::

  local smtp = require("suricata.smtp")

Setup
*****

If your purpose is to create a logging script, initialize the buffer as:

::

  function init (args)
     local needs = {}
     needs["protocol"] = "smtp"
     return needs
  end

Otherwise if a detection script::

  function init (args)
    return {}
  end

API
***

Transaction
===========

SMTP is transaction based, and the current transaction must be
obtained before use::

  local tx, err = smtp.get_tx()
  if tx == nil then
      print(err)
  end

All other functions are methods on the transaction table.

Transaction Methods
===================

``get_mime_field(name)``
------------------------

Get a specific MIME header field by name from the SMTP transaction.

Example::

  local tx = smtp.get_tx()
  local encoding = tx:get_mime_field("Content-Transfer-Encoding")
  if encoding ~= nil then
      print("Encoding: " .. subject)
  end

``get_mime_list()``
-------------------

Get all the MIME header field names from the SMTP transaction as a
table.

Example::

  local tx = smtp.get_tx()
  local mime_fields = tx:get_mime_list()
  if mime_fields ~= nil then
      for i, name in pairs(mime_fields) do
          local value = tx:get_mime_field(name)
          print(name .. ": " .. value)
      end
  end

``get_mail_from()``
-------------------

Get the sender email address from the MAIL FROM command.

Example::

  local tx = smtp.get_tx()
  local mail_from = tx:get_mail_from()
  if mail_from ~= nil then
      print("Sender: " .. mail_from)
  end

``get_rcpt_list()``
-------------------

Get all recipient email addresses from RCPT TO commands as a table.

Example::

  local tx = smtp.get_tx()
  local recipients = tx:get_rcpt_list()
  if recipients ~= nil then
      for i, recipient in pairs(recipients) do
          print("Recipient " .. i .. ": " .. recipient)
      end
  end
