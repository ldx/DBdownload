### DBdownload

**DBdownload** is a simple [Dropbox](http://www.dropbox.com) client written in
Python. It does one-way synchronization from a directory in your Dropbox
account to a local directory. The local folder will be kept in sync with your
Dropbox folder, so if anything is updated, removed or added on Dropbox, it will
be downloaded and kept updated in your local folder. Local changes will be
overwritten - it's one-way only.

### Why?

I just tried to install and use the official Dropbox client on a low-end VPS,
and the OOM kept killing it because it was such a memory hog.  Frustrated by
not being able no simply sync a folder to my box, I checked out whether I
could hack together a simple client which only did one-way synchronization.
DBdownload is the result.

### Install

Set up a new [virtualenv](http://www.virtualenv.org/en/1.9.X/), e.g. on Ubuntu:

    $ sudo apt-get install virtualenv virtualenvwrapper
    $ . /etc/bash_completion.d/virtualenvwrapper
    $ mkvirtualenv dbdownload

You need the [Dropbox Python SDK](https://www.dropbox.com/developers/core/setup#python):

    $ wget https://www.dropbox.com/static/developers/dropbox-python-sdk-1.5.1.zip
    $ unzip dropbox-python-sdk-1.5.1.zip && cd dropbox-python-sdk-1.5.1
    $ python setup.py install

Fetch and install **DBdownload**:

    $ git clone https://github.com/ldx/DBdownload.git
    $ cd DBdownload
    $ setup.py install

### Use

Just launch **DBdownload** and specify the source Dropbox directory you would
like to sync to your local computer, and the target folder it should be synced
into. If the local folder does not exist **DBdownload** will create it, if it
is used, it will be cleared first.

    $ dbdownload -s test -t /tmp/test
    URL: https://www.dropbox.com/1/oauth/authorize?oauth_token=fjlkadf8a7dfjxy
    Please authorize this URL in the browser and then press enter

If this is the first time **DBdownload** is started, it will request access to
your Dropbox data. Just open the link in your browser and allow access.

![Dropbox authentication](http://nilvec.com/static/images/db_oauth.png)

![Dropbox authentication](http://nilvec.com/static/images/db_oauth_success.png)

Press enter, and if you have allowed access, **DBdownload** should start
synchronizing your Dropbox source folder to the target directory.

**DBdownload** has quite some flags and optional parameters, check them out:

    $ dbdownload --help
