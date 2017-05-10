Flowint
=======

Flowint is a precursor to the Global Variables task we will be adding
to the engine very soon, which will allow the capture, storage and
comparison of data in a variable.  It will be as the name implies
Global. So you can compare data from packets in unrelated streams.

Flowint allows storage and mathematical operations using variables. It
operates much like flowbits but with the addition of mathematical
capabilities and the fact that an integer can be stored and
manipulated, not just a flag set. We can use this for a number of very
useful things, such as counting occurrences, adding or subtracting
occurrences, or doing thresholding within a stream in relation to
multiple factors. This will be expanded to a global context very soon,
so users can perform these operations between streams.

The syntax is as follows:

flowint: , ;

Define a var (not required), or check that one is set or not set.

flowint: , , ;

flowint: , < +,-,=,>,<,>=,<=,==, != >, ;

Compare or alter a var. Add, subtract, compare greater than or less
than, greater than or equal to, and less than or equal to are
available. The item to compare with can be an integer or another
variable.

________________________________________

For example, if you want to count how many times a username is seen in
a particular stream and alert if it is over 5.

::

  alert tcp any any -> any any (msg:"Counting Usernames"; content:"jonkman"; \
        flowint: usernamecount, +, 1; noalert;)

This will count each occurrence and increment the var usernamecount
and not generate an alert for each.

Now say we want to generate an alert if there are more than five hits
in the stream.

::

  alert tcp any any -> any any (msg:"More than Five Usernames!"; content:"jonkman"; \
        flowint: usernamecount, +, 1; flowint:usernamecount, >, 5;)

So we'll get an alert ONLY if usernamecount is over five.

So now let’s say we want to get an alert as above but NOT if there
have been more occurrences of that username logging out. Assuming this
particular protocol indicates a log out with "jonkman logout", let’s
try:

::

  alert tcp any any -> any any (msg:"Username Logged out"; content:"logout jonkman"; \
        flowint: usernamecount, -, 1; flowint:usernamecount, >, 5;)

So now we'll get an alert ONLY if there are more than five active
logins for this particular username.

This is a rather simplistic example, but I believe it shows the power
of what such a simple function can do for rule writing. I see a lot of
applications in things like login tracking, IRC state machines,
malware tracking, and brute force login detection.

Let’s say we're tracking a protocol that normally allows five login
fails per connection, but we have vulnerability where an attacker can
continue to login after that five attempts and we need to know about
it.

::

  alert tcp any any -> any any (msg:"Start a login count"; content:"login failed"; \
        flowint:loginfail, notset; flowint:loginfail, =, 1; noalert;)

So we detect the initial fail if the variable is not yet set and set
it to 1 if so. Our first hit.

::

  alert tcp any any -> any any (msg:"Counting Logins"; content:"login failed"; \
        flowint:loginfail, isset; flowint:loginfail, +, 1; noalert;)

We are now incrementing the counter if it's set.

::

  alert tcp any any -> any any (msg:"More than Five login fails in a Stream"; \
        content:"login failed"; flowint:loginfail, isset; flowint:loginfail, >, 5;)


Now we'll generate an alert if we cross five login fails in the same
stream.

But let's also say we also need alert if there are two successful
logins and a failed login after that.

::

  alert tcp any any -> any any (msg:"Counting Good Logins"; content:"login successful"; \
        flowint:loginsuccess, +, 1; noalert;)

Here we're counting good logins, so now we'll count good logins
relevant to fails:

::

  alert tcp any any -> any any (msg:"Login fail after two successes"; \
        content:"login failed"; flowint:loginsuccess, isset; flowint:loginsuccess, =, 2;)

Here are some other general examples:

::

  alert tcp any any -> any any (msg:"Setting a flowint counter"; content:"GET"; \
        flowint:myvar, notset; flowint:maxvar,notset;                           \
        flowint:myvar,=,1; flowint: maxvar,=,6;)

::

  alert tcp any any -> any any (msg:"Adding to flowint counter";                \
        content:"Unauthorized"; flowint:myvar,isset; flowint: myvar,+,2;)

::

  alert tcp any any -> any any (msg:"if the flowint counter is 3 create a new counter"; \
        content:"Unauthorized"; flowint:myvar, isset; flowint:myvar,==,3; \
        flowint:cntpackets,notset; flowint:cntpackets, =, 0;)

::

  alert tcp any any -> any any (msg:"count the rest without generating alerts"; \
        flowint:cntpackets,isset; flowint:cntpackets, +, 1; noalert;)

::

  alert tcp any any -> any any (msg:"fire this when it reach 6";                \
        flowint: cntpackets, isset;                                             \
        flowint: maxvar,isset; flowint: cntpackets, ==, maxvar;)
