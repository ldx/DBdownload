#!/usr/bin/env python

import json
import locale
import logging
import os
import posixpath as dropboxpath
import subprocess
import sys
import time
from base64 import b64decode
from ConfigParser import SafeConfigParser
from optparse import OptionParser

import dropbox
import jsonpickle

# Globals.
# Got encoded dropbox app key at
# https://dl-web.dropbox.com/spa/pjlfdak1tmznswp/api_keys.js/public/index.html
APP_KEY = 'bYeHLWKRctA=|ld63MffhrcyQrbyLTeKvTqxE5cQ3ed1YL2q87GOL/g=='
LOGGER = 'dbdownload'
VERSION = '0.0'

# Initialize version from a number given in setup.py.
try:
    import pkg_resources  # Part of setuptools.
except ImportError:  # Standalone script?
    pass
else:
    try:
        VERSION = pkg_resources.require('dbdownload')[0].version
    except pkg_resources.DistributionNotFound:  # standalone script?
        pass


def decode_dropbox_key(key):
    key, secret = key.split('|')
    key = b64decode(key)
    key = [ord(x) for x in key]
    secret = b64decode(secret)

    s = range(256)
    y = 0
    for x in xrange(256):
        y = (y + s[len(key)] + key[x % len(key)]) % 256
        s[x], s[y] = s[y], s[x]

    x = y = 0
    result = []
    for z in range(len(secret)):
        x = (x + 1) % 256
        y = (y + s[x]) % 256
        s[x], s[y] = s[y], s[x]
        k = s[(s[x] + s[y]) % 256]
        result.append(chr((k ^ ord(secret[z])) % 256))

    # key = ''.join([chr(a) for a in key])
    # return '|'.join([b64encode(key), b64encode(''.join(result))])
    return ''.join(result).split('?', 2)


class DBDownload(object):

    def __init__(self, remote_dir, local_dir, cache_file, sleep=600, prg=None):
        self._logger = logging.getLogger(LOGGER)

        self.remote_dir = remote_dir.lower()
        if not self.remote_dir.startswith(dropboxpath.sep):
            self.remote_dir = dropboxpath.join(dropboxpath.sep,
                                               self.remote_dir)
        if self.remote_dir.endswith(dropboxpath.sep):
            self.remote_dir, _ = dropboxpath.split(self.remote_dir)

        self.local_dir = local_dir

        self.cache_file = cache_file

        self.sleep = int(sleep)  # Can be string if read from conf.

        self.executable = prg

        self._tree = {}
        self._token = None
        self._cursor = None
        self._load_state()

        if self._token is None:
            key, secret = decode_dropbox_key(APP_KEY)
            auth_flow = dropbox.DropboxOAuth2FlowNoRedirect(key, secret)
            auth_url = auth_flow.start()
            print "1. Go to: " + auth_url
            print "2. Click \"Allow\" (you might have to log in first)."
            print "3. Copy the authorization code."
            auth_code = raw_input("Enter the authorization code here: ").strip()
            try:
                oauth_result = auth_flow.finish(auth_code)
            except Exception:
                self._logger.error("Invalid authorization code. Exiting.")
                sys.exit(1)
            self._token = oauth_result.access_token

        try:
            self.client = dropbox.Dropbox(self._token)
        except Exception as e:
            self._logger.exception("Unable to connect to Dropbox.")
            sys.exit(1)

    def reset(self):
        self._logger.debug('resetting local state')
        self._tree = {}
        self._cursor = None
        self._save_state()

    def start(self):
        try:
            self._monitor()
        except KeyboardInterrupt:
            pass

    def _local2remote(self, local):
        local_comp = self.local_dir.split(os.path.sep)
        rootlen = len(local_comp)
        if not local_comp[-1]:  # Trailing slash.
            rootlen -= 1
        x = local.split(os.path.sep)[rootlen:]
        remote = dropboxpath.join(self.remote_dir, *x)
        return remote

    def _remote2local(self, remote):
        remote_comp = self.remote_dir.split(dropboxpath.sep)
        rootlen = len(remote_comp)
        if not remote_comp[-1]:  # Trailing slash.
            rootlen -= 1
        x = remote.split(dropboxpath.sep)[rootlen:]
        local = os.path.join(self.local_dir, *x)
        return local

    def _monitor(self):
        self._mkdir(self.local_dir)  # Make sure root directory exists.

        tree = {}
        while True:
            # Check for anything missing locally.
            changed = self._check_missing()

            # If we don't have a cursor yet, call files_list_folder
            try:
                if self._cursor is None:
                    remote_dir = "" if self.remote_dir == dropboxpath.sep else self.remote_dir
                    result = self.client.files_list_folder(remote_dir, recursive=True)
                else:
                    result = self.client.files_list_folder_continue(self._cursor)
            except Exception as e:
                self._logger.error('error getting file list')
                self._logger.exception(e)
                continue

            for entry in result.entries:
                if os.path.commonprefix([entry.path_lower, self.remote_dir]) == self.remote_dir:
                    tree[entry.path_lower] = entry

            self._cursor = result.cursor

            if not result.has_more:
                if tree:
                    self._apply_delta(tree)
                    merged = dict(self._tree.items() + tree.items())
                    self._tree = dict([(k, v) for k, v in merged.items() if v])
                    changed = True

                rv = self._cleanup_target()  # Remove local changes.
                if not changed:
                    changed = rv
                self._save_state()

                if changed and self.executable:
                    self._launch(self.executable)

                # Done processing delta, sleep and check again.
                tree = {}
                self._logger.debug('sleeping for %d seconds' % self.sleep)
                time.sleep(self.sleep)

    # Launch a program if anything has changed.
    def _launch(self, prg):
        try:
            subprocess.Popen([prg], shell=True, stdin=None, stdout=None,
                             stderr=None, close_fds=True)
        except Exception as e:
            self._logger.error('error launching program')
            self._logger.exception(e)

    # Load state from our local cache.
    def _load_state(self):
        cachefile = os.path.expanduser(self.cache_file)

        if not os.path.exists(cachefile):
            self._logger.warn('Cache file not found: %s' % cachefile)
            self.reset()
            return

        try:
            with open(cachefile, 'r') as f:
                dir_changed = False
                try:
                    line = f.readline()  # Dropbox directory.
                    directory = json.loads(line)
                    if directory != self.remote_dir:  # Don't use state.
                        self._logger.info(u'remote dir changed "%s" -> "%s"' %
                                          (directory, self.remote_dir))
                        dir_changed = True
                except Exception as e:
                    self._logger.warn('can\'t load cache state')
                    self._logger.exception(e)

                try:
                    line = f.readline()  # Token.
                    self._token = json.loads(line)
                    self._logger.debug('loaded token')
                except Exception as e:
                    self._logger.warn('can\'t load token from cache state')
                    self._logger.exception(e)
                if dir_changed:
                    return

                try:
                    line = f.readline()  # Cursor.
                    self._cursor = json.loads(line)
                    self._logger.debug('loaded delta cursor')
                except Exception as e:
                    self._logger.warn('can\'t load delta cursor from cache state')
                    self._logger.exception(e)

                try:
                    line = f.readline()  # Tree.
                    self._tree = jsonpickle.decode(line)
                    self._logger.debug('loaded local tree')
                except Exception as e:
                    self._logger.warn('can\'t load local tree from cache state')
                    self._logger.exception(e)
        except Exception as e:
            self._logger.error('error opening cache file')
            self._logger.exception(e)

    # Update our local state file.
    def _save_state(self):
        with open(os.path.expanduser(self.cache_file), 'w') as f:
            f.write(''.join([json.dumps(self.remote_dir), '\n']))
            f.write(''.join([json.dumps(self._token), '\n']))
            f.write(''.join([json.dumps(self._cursor), '\n']))
            f.write(''.join([jsonpickle.encode(self._tree), '\n']))

    # Check for files/folders missing or modified locally.
    def _check_missing(self):
        dirs = []
        files = []
        changed = False
        for key, meta in self._tree.items():
            if not meta or isinstance(meta, dropbox.files.DeletedMetadata):
                continue

            local_path = unicode(self._remote2local(meta.path_display))

            if not os.path.exists(local_path.encode('utf-8')):
                if type(meta) is dropbox.files.FolderMetadata:
                    dirs.append((key, local_path))
                else:
                    t = time.mktime(meta.client_modified.timetuple())
                    files.append((key, local_path, t))

            elif type(meta) is dropbox.files.FileMetadata:
                t = time.mktime(meta.client_modified.timetuple())
                stat = os.stat(local_path.encode('utf-8'))
                if stat.st_mtime != t:
                    self._logger.debug(u'%s has been modified locally' %
                                       local_path)
                    files.append((key, local_path, t))

        dirs.sort()  # Make sure we're creating them in order.

        for _, d in dirs:
            self._mkdir(d)
            changed = True

        for k, f, t in files:
            self._get_file(k, f, t)
            changed = True

        return changed

    # Apply any outstanding change.
    def _apply_delta(self, tree):
        self._logger.debug('applying changes in tree')
        rm = [self._tree[n].path_display for n in tree if not tree[n] and n in
              self._tree and self._tree[n]]
        rm.sort(reverse=True)
        for path in rm:
            self._remove(self._remote2local(path))  # Remove file/directory.

        dirs = sorted([n for n in tree if tree[n] and type(tree[n]) is dropbox.files.FolderMetadata])

        for d in dirs:
            # Directories no longer have revision info in v2, so just make it regardless
            self._mkdir(self._remote2local(tree[d].path_display))

        files = [n for n in tree if tree[n] and type(tree[n]) is dropbox.files.FileMetadata]

        for f in files:
            rev = f in tree and tree[f].rev or -1
            oldrev = f in self._tree \
                     and not isinstance(
                         self._tree[f], dropbox.files.DeletedMetadata) \
                     and self._tree[f].rev \
                     or -1
            # Revisions are no longer simple ints, so the best we can do is check equality, not order
            if oldrev != rev:
                local_path = self._remote2local(tree[f].path_display)
                self._get_file(f, local_path, time.mktime(tree[f].client_modified.timetuple()))

    # Remove anything that is not in dropbox.
    def _cleanup_target(self):
        def _is_deleted(key, path):
            return (key not in self._tree \
                    or self._remote2local(self._tree[key].path_display).lower() != path.lower() \
                    or isinstance(self._tree[key], dropbox.files.DeletedMetadata))

        self._logger.debug('cleanup using merged tree')
        changed = False
        for root, dirs, files in os.walk(self.local_dir):
            rmdirs = []
            for d in dirs:
                path = os.path.join(root, d).decode('utf-8')
                key = self._local2remote(path).lower()
                if _is_deleted(key, path):
                    rmdirs.append(d)
                    self._logger.info(u'RM -RF %s' % path)
                    self._rmrf(path)
                    changed = True

            for d in rmdirs:
                dirs.remove(d)

            for f in files:
                path = os.path.join(root, f).decode('utf-8')
                key = self._local2remote(path).lower()
                if _is_deleted(key, path):
                    self._logger.info(u'RM %s' % path)
                    self._rm(path)
                    changed = True

        return changed

    def _rmrf(self, folder):
        for path in (os.path.join(folder, f) for f in os.listdir(folder)):
            if os.path.isdir(path):
                self._rmrf(path)
            else:
                os.unlink(path)
        os.rmdir(folder)

    def _rm(self, path):
        os.unlink(path)

    def _remove(self, path):
        if not os.path.exists(path.encode('utf-8')):
            return
        if os.path.isdir(path):
            self._rmrf(path)
        else:
            self._rm(path)

    def _mkdir(self, d):
        if os.path.isfile(d):
            os.unlink(d)
        if not os.path.exists(d.encode('utf-8')):
            self._logger.info(u'MKDIR %s' % (unicode(d)))
            os.mkdir(d)

    def _get_file(self, from_path, to_path, modified=None):
        self._logger.info(u'FETCH %s -> %s' %
                          (unicode(from_path), unicode(to_path)))
        try:
            self.client.files_download_to_file(to_path.encode('utf-8'), from_path.encode('utf-8'))
        except Exception as e:
            self._logger.error('error fetching file')
            self._logger.exception(e)
            return  # Will check later if we've got everything.

        if modified:
            os.utime(to_path.encode('utf-8'), (modified, modified))


class FakeSecHead(object):

    def __init__(self, fp):
        self.fp = fp
        self.sechead = '[asection]\n'

    def readline(self):
        if self.sechead:
            try:
                return self.sechead
            finally:
                self.sechead = None
        else:
            return self.fp.readline()


def parse_config(cfg, opts):
    parser = SafeConfigParser()
    try:
        fp = open(os.path.expanduser(cfg), 'r')
    except Exception:
        print 'Warning: can\'t open %s, using default values' % cfg
        return
    parser.readfp(FakeSecHead(fp))
    fp.close()

    for section_name in parser.sections():
        for name, value in parser.items(section_name):
            if name not in opts:
                raise Exception(u'Invalid config file option \'%s\'' % name)
            opts[name] = value


def create_logger(log, verbose):
    FORMAT = '%(asctime)-15s %(message)s'
    console = log.strip() == '-'
    if console:
        logging.basicConfig(format=FORMAT)
    logger = logging.getLogger(LOGGER)
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    if not console:
        fh = logging.FileHandler(log)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter(FORMAT)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger


def main():
    options = {'log': '-', 'config': '~/dbdownload.conf',
               'cache': '~/.dbdownload.cache', 'interval': 300,
               'source': None, 'target': None, 'verbose': False, 'reset': False,
               'exec': None, 'authorizeonly': False}

    # First parse any command line arguments.
    parser = OptionParser(description='Do one-way Dropbox synchronization')
    parser.add_option('--interval', '-i', type=int, help='check interval')
    parser.add_option('--config', '-c', help='configuration file')
    parser.add_option('--cache', '-a', help='cache file')
    parser.add_option('--log', '-l', help='logfile (pass - for console)')
    parser.add_option('--source', '-s',
                      help='source Dropbox directory to synchronize')
    parser.add_option('--target', '-t', help='local directory to download to')
    parser.add_option('--verbose', '-v', action='store_true',
                      help='enable verbose logging')
    parser.add_option('--reset', '-r', action='store_true',
                      help='reset synchronization')
    parser.add_option('--authorizeonly', '-u', action='store_true',
                      help='only authorize application and exit')
    parser.add_option('--exec', '-x',
                      help='execute program when directory has changed')
    (opts, args) = parser.parse_args()
    if args:
        print 'Leftover command line arguments', args
        sys.exit(1)

    # Parse configuration file.
    parse_config((opts.config and [opts.config] or
                  [options['config']])[0], options)

    # Override parameters from config file with cmdline options.
    for a in options:
        v = getattr(opts, a)
        if v:
            options[a] = v

    if not options['source'] or not options['target']:
        error_msg = 'Please provide source and target directories'
        sys.stderr.write('Error: %s\n' % error_msg)
        sys.exit(-1)

    locale.setlocale(locale.LC_ALL, 'C')  # To parse time correctly.

    logger = create_logger(options['log'], options['verbose'])
    logger.info(u'*** DBdownload v%s starting up ***' % VERSION)

    dl = DBDownload(options['source'], options['target'], options['cache'],
                    options['interval'], options['exec'])
    if options['reset']:
        dl.reset()

    if not opts.authorizeonly:
        dl.start()
    else:
        dl.reset()

if __name__ == '__main__':
    main()
