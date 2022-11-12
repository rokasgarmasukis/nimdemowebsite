import db_sqlite
import jester
import logging
import os
import parsecfg
import strutils
import times
import uri
import code/database_utils
import code/password_utils

#Load config files
let dict = loadConfig("config/config.cfg")

let db_user = dict.getSectionValue("Database", "user")
let db_pass   = dict.getSectionValue("Database", "pass")
let db_name   = dict.getSectionValue("Database", "name")
let db_host   = dict.getSectionValue("Database", "host")

let mainURL   = dict.getSectionValue("Server", "url")
let mainPort  = parseInt dict.getSectionValue("Server", "port")
let mainWebsite = dict.getSectionValue("Server", "website")

var db: DbConn

settings:
  port = Port(mainPort)
  bindAddr = mainURL

#User data
type
  TData* = ref object of RootObj
    loggedIn*: bool
    userid, username*, userpass*, email*: string
    req*: Request

proc init(c: var TData) =
  ## Empty out user session data
  c.userpass = ""
  c.username = ""
  c.userid = ""
  c.loggedIn = false

func loggedIn(c: TData): bool =
  ## Check if user is logged in by verifying that c.username exists
  c.username.len > 0

proc checkLoggedIn(c: var TData) =
  ## Check if user is logged in
  
  # Get the users cookie named `sid`. If it does not exist, return
  if not c.req.cookies.hasKey("sid"): return

  # Assign cookie to `let sid`
  let sid = c.req.cookies["sid"]

  # Update the value lastModified for the user in the
  # table session where the sid and IP match. If there's
  # any results (above 0) assign values
  if execAffectedRows(db, sql("UPDATE session SET lastModified = " & $toInt(epochTime()) & " " & "WHERE ip = ? AND key = ?"), c.req.ip, sid ) > 0:

    # Get user data based on userID rom session table
    # Assing values to user details - `c`
    c.userid = getValue(db, sql"SELECT userid FROM session WHERE ip = ? AND key = ?", c.req.ip, sid)

    # Get user data based on userID from person table
    let row = getRow(db, sql"SELECT name, email, status FROM person WHERE id = ?", c.userid)

    # Assign user data
    c.username = row[0]
    c.email = toLowerAscii(row[1])

    # Update our session table with info about activity
    discard tryExec(db, sql"UPDATE person SET lastOnline = ? WHERE id = ?", toInt(epochTime()), c.userid)

  else:
    # If the user is not found in the session table
    c.loggedIn = false

