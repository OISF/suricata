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

How long a transaction handle is valid
======================================

A handle is valid while its transaction remains open: it is resolved
by identity within the flow of the current invocation, so a method
call after the transaction is gone (freed once it is complete,
inspected and logged, or at flow teardown) aborts the script with a
Lua error - counted in ``detect.lua.errors`` for detection scripts -
and never returns data from another transaction or flow. The sandbox blocks
``pcall``/``xpcall``, so a detection script cannot catch the error
(output scripts are unsandboxed). Keep handles short-lived: do not
cache them across packets.

``smtp.get_tx()`` with no transaction available returns the usual
``nil`` plus ``error: no SMTP transaction found`` - the invocation
continues and nothing is logged or counted - which is what keeps it
distinguishable from a stale handle.

``get_mail_from()`` on a transaction whose field has not been seen yet
returns a single ``nil`` with no error, so an empty ``mail_from`` is
distinguishable from a stale handle. ``get_mime_field()`` and
``get_mime_list()`` return ``nil`` plus an error before DATA or for a
field not seen.

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
table, starting with the first header.

.. note::

   The list is indexed from the first header. Earlier releases (up to
   8.0.x as of this change) started at the header after the first
   one, so scripts written against those shift by one.

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
