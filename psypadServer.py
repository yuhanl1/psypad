#!/usr/bin/python
# -*- coding: UTF-8 -*-

import csv
import MySQLdb
import datetime
import time
import sys
import socket
import thread
import hashlib
from Crypto.PublicKey import RSA


# CSV File
def writeToCSV(data,filename):
    # data is a list of lists(rows)
    with open(filename, 'w', newline='', encoding='utf8') as f:
        writer = csv.writer(f)
        writer.writerows(data)


# Time Access
def getDate():
    return datetime.datetime.now().strftime('%Y-%m-%d')


def getTime():
    return datetime.datetime.now().strftime('%H:%M:%S')


#Data Encryption
def getEncrypt(password):
    m = hashlib.md5()
    m.update(password)
    d = m.digest()
    #print len(d)
    return d.encode('base64', 'strict')


def getPlainText(encryptText):
    return encryptText.decode('base64','strict')


# Data Access
def connectToDB(host, db_user, db_password, schema_name):
    return MySQLdb.connect(host, db_user, db_password, schema_name, charset='utf8')


class psypadServer():
    def __init__(self, host = 'localhost', db_user = 'root', db_password = '1234', schema_name = 'psypad', validPrefix = 'TS'):
        self.host = host
        self.port = 8000
        self.db_user = db_user
        self.db_password = db_password
        self.schema_name = schema_name
        self.validPrefix = validPrefix

    # user Table Database Define
    # +----------+-------------+------+-----+---------+----------------+
    # | Field    | Type        | Null | Key | Default | Extra          |
    # +----------+-------------+------+-----+---------+----------------+
    # | id       | int(11)     | NO   | PRI | NULL    | auto_increment |
    # | rego     | varchar(20) | NO   | UNI | NULL    |                |
    # | password | varchar(32) | NO   |     | NULL    |                |
    # +----------+-------------+------+-----+---------+----------------+
    def selectAllUser(self):
        db = connectToDB(self.host,self.db_user,self.db_password,self.schema_name)
        cursor = db.cursor()
        sql = "SELECT * FROM user"
        try:
            cursor.execute(sql)
            db.close()
            return cursor.fetchall()
        except:
            print "Error: unable to fetch rego data"
            db.close()
            return []

    def selectUser(self,sel_user):
        db = connectToDB(self.host,self.db_user,self.db_password,self.schema_name)
        cursor = db.cursor()
        sql = "SELECT id FROM user WHERE rego = '%s'" % (sel_user)
        try:
            cursor.execute(sql)
            db.close()
            return cursor.fetchall()
        except:
            print "Error: unable to fetch rego data"
            db.close()
            return []

    def selectUserPassword(self,user_id):
        db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
        cursor = db.cursor()
        sql = "SELECT password FROM user WHERE rego = '%s'" % (user_id)
        try:
            cursor.execute(sql)
            db.close()
            return cursor.fetchall()
        except:
            print "Error: unable to fetch rego data"
            db.close()
            return []

    def insertUser(self,new_rego, pwd):
        db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
        cursor = db.cursor()
        sql = "INSERT INTO user (rego,password) VALUES ('%s','%s')" % (new_rego,pwd)
        try:
            cursor.execute(sql)
            db.commit()
            return True
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            db.rollback()
            print "Error(" + e[0] + "): unable to insert rego. Reason: " + e[1]
            return False

    def updateUser(self,new_rego, new_pwd):
        db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
        cursor = db.cursor()
        sql = "UPDATE user SET password = '%s' WHERE rego = '%s'" % (new_pwd, new_rego)
        try:
            cursor.execute(sql)
            db.commit()
            return True
        except:
            db.rollback()
            print "Error: unable to change the password"
            return False

    def deleteUser(self,del_user):
        db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
        cursor = db.cursor()
        sql = "DELETE FROM user WHERE rego = '%s'" % (del_user)
        try:
            cursor.execute(sql)
            db.commit()
            db.close()
            return True
        except:
            db.rollback()
            print "Error: unable to delete rego"
            return False

    # record Table Database Define
    # +------------+---------+------+-----+---------+----------------+
    # | Field      | Type    | Null | Key | Default | Extra          |
    # +------------+---------+------+-----+---------+----------------+
    # | record_id  | int(11) | NO   | PRI | NULL    | auto_increment |
    # | user_id    | int(11) | NO   | MUL | NULL    |                |
    # | threshold1 | int(11) | YES  |     | NULL    |                |
    # | threshold2 | int(11) | YES  |     | NULL    |                |
    # | date       | date    | YES  |     | NULL    |                |
    # | time       | time    | YES  |     | NULL    |                |
    # +------------+---------+------+-----+---------+----------------+
    def selectAllRecords(self):
        db = connectToDB(self.host,self.db_user,self.db_password,self.schema_name)
        cursor = db.cursor()
        sql = "SELECT * FROM record"
        try:
            cursor.execute(sql)
            db.close()
            return cursor.fetchall()
        except:
            print "Error: unable to fetch record data"
            db.close()
            return []

    def selectRecordByUser(self, sel_user_id):
        db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
        cursor = db.cursor()
        sql = "SELECT * FROM record WHERE user_id = '%s'" % (sel_user_id)
        try:
            cursor.execute(sql)
            db.close()
            return cursor.fetchall()
        except:
            print "Error: unable to fetch record data"
            db.close()
            return []

    def selectRecordByThreshold1(self, larger, value):
        # larger choose from ['>','<','>=','<=','=']
        db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
        cursor = db.cursor()
        sql = "SELECT * FROM record WHERE threshold1 '%s' '%d'" % (larger, value)
        try:
            cursor.execute(sql)
            db.close()
            return cursor.fetchall()
        except:
            print "Error: unable to fetch record data"
            db.close()
            return []

    def selectRecordByThreshold2(self, larger, value):
        # larger choose from ['>','<','>=','<=','=']
        db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
        cursor = db.cursor()
        sql = "SELECT * FROM record WHERE threshold2 '%s' '%d'" % (larger, value)
        try:
            cursor.execute(sql)
            db.close()
            return cursor.fetchall()
        except:
            print "Error: unable to fetch record data"
            db.close()
            return []

    def insertRecord(self, user_id, threshold1, threshold2, date, time):
         db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
         cursor = db.cursor()
         sql = "INSERT INTO record (user_id,threshold1,threshold2,date,time) VALUES ('%s','%d','%d','%s','%s')" % (user_id, threshold1, threshold2, date, time)
         try:
             cursor.execute(sql)
             db.commit()
             return True
         except:
             db.rollback()
             print "Error: unable to insert record"
             return False

    def deleteRecordsByUser(self, del_user):
        db = connectToDB(self.host, self.db_user, self.db_password, self.schema_name)
        cursor = db.cursor()
        sql = "DELETE FROM record WHERE user_id = '%s'" % (del_user)
        try:
            cursor.execute(sql)
            db.commit()
            db.close()
            return True
        except:
            db.rollback()
            print "Error: unable to delete record"
            return False

    # Logic Functions - Rego
    def checkValidPrefix(self,validPrefix, rego):
        # Return True: Valid
        # Return False: Invalid
        return rego.upper().startswith(validPrefix.upper())

    def checkNotDuplication(self,rego):
        # Return True: Not Duplicated
        # Return False: Duplicated
        existedRego = self.selectUser(rego)
        if len(existedRego) == 0:
            return True
        else:
            return False

    def register(self,rego, pwd):
        if self.checkValidPrefix(self.validPrefix,rego):
            if self.checkNotDuplication(rego):
                if len(pwd) > 0:
                    success = self.insertUser(rego,pwd)
                    if success:
                        return 'Success!'
                    else:
                        return 'Error: database unable to insert rego.'
                else:
                    return 'Error: password is empty.'
            else:
                return 'Error: rego is duplicated.'
        else:
            return 'Error: rego is in invalid form.'

    def getRegoID(self,rego):
        existedRego = self.selectUser(rego)
        if len(existedRego) == 0:
            return None
        else:
            return existedRego[0][0]

    def getPassword(self,rego):
        userPwd = self.selectUserPassword(rego)
        if len(userPwd) == 0:
            return None
        else:
            return userPwd[0][0]


    def login(self, user_rego, raw_pwd):
        if not self.checkNotDuplication(user_rego):
            store_pwd = self.getPassword(user_rego)
            if getEncrypt(raw_pwd) == store_pwd:
                return 'Success'
            else:
                return 'Invalid Password'
        else:
            return 'Invalid User ID'


    def changePassword(self,user_rego, old_pwd, new_pwd):
        authentication = self.login(user_rego,old_pwd)
        if authentication == 'Success':
            if self.updateUser(user_rego,getEncrypt(new_pwd)):
                return 'Success'
            else:
                return 'Database Error'
        else:
            return authentication


    # Logic Functions - Records
    def storeRecord(self, rego, threshold1, threshold2):
        user_id = self.getRegoID(rego)
        if user_id != None:
            success = self.insertRecord(user_id,int(threshold1),int(threshold2),getDate(),getTime())
            if success:
                return 'Success'
            else:
                return 'Error: database unable to insert record.'
        else:
            return 'Error: rego is invalid.'

    def getAllRecordsToCSVFile(self,filename):
        print 'Reading Records...'
        data = self.selectAllRecords()
        print 'Transforming to CSV File...'
        writeToCSV(data=data,filename=filename)
        print 'Done.'

    def analyseRecordsByUser(self,user_rego):
        records = self.selectRecordByUser(self.getRegoID(user_rego))
        total_test = len(records)
        days_str_set = set()
        days_datetime_list = []
        if total_test == 0:
            day_in_row = 0
        else:
            day_in_row = 1
        for record in records:
            date = record[4]
            #print type(date)
            days_str_set.add(date)
        total_day = len(days_str_set)
        #format = '%Y-%m-%d'
        for day in days_str_set:
            days_datetime_list.append(day)
        for i in range(len(days_datetime_list)-1,0,-1):
            current = days_datetime_list[i]
            last = days_datetime_list[i-1]
            interval_day = (current - last).days
            if interval_day == 1:
                day_in_row += 1
            else:
                break
        return (total_test,total_day,day_in_row)

    #Socket
    def child_connection(self, sock, connection):
        buf = connection.recv(1024)
        buf = str(buf)
        if buf.startswith('Check'):
            print 'Check Rego'
            userID = buf[6:].upper()
            if self.checkNotDuplication(userID):
                connection.send("Invalid")
            else:
                connection.send("Valid")

        elif buf.startswith('Login'):#Login:ID:ts123,PWD:lyh
            print 'Login'
            info = buf[6:]
            pwd_index = info.find('PWD:')
            userID = info[3:pwd_index-1].upper()
            userPwd = info[pwd_index+4:]
            # print userID, userPwd
            connection.send(self.login(userID,userPwd))

        elif buf.startswith('Register'):#Register:ID:ts123,PWD:lyh
            print 'Register Rego'
            info = buf[9:]
            pwd_index = info.find('PWD:')
            userID = info[3:pwd_index-1].upper()
            userPwd = info[pwd_index + 4:]
            print userID,userPwd,getEncrypt(userPwd)
            if self.checkValidPrefix(self.validPrefix,userID):
                if self.checkNotDuplication(userID):
                    if self.insertUser(userID,getEncrypt(userPwd)):
                        connection.send("Success")
                    else:
                        connection.send("Database Error")
                else:
                    connection.send("User Existed")
            else:
                connection.send("Invalid Prefix")

        elif buf.startswith('ChangePWD'): # ChangePWD:ID:ts123,OLD_PWD:lyh,NEW_PWD:LYH
            print 'Change Password'
            info = buf[10:]
            old_pwd_index = info.find('OLD_PWD:')
            new_pwd_index = info.find('NEW_PWD:')
            userID = info[3:old_pwd_index - 1].upper()
            old_userPwd = info[old_pwd_index + 8: new_pwd_index - 1]
            new_userPwd = info[new_pwd_index + 8:]
            connection.send(self.changePassword(userID,old_userPwd,new_userPwd))

        elif buf.startswith('Record'):
            print 'Store Record'
            content = buf[7:].upper()
            contents = content.split(';')
            connection.send(self.storeRecord(contents[0],contents[1],contents[2]))

        elif buf.startswith('AnalyseRecord'):#AnalyseRecord:TS123
            print 'Analyse Record'
            user_rego = buf[14:].upper()
            results = self.analyseRecordsByUser(user_rego)
            resultStr = str(results[0]) + ',' + str(results[1]) + ',' + str(results[2])
            connection.send(resultStr) #'1,2,3'

        elif buf.startswith('Download'):
            print 'Download Records to CSV file'
            filename = buf[9:]
            self.getAllRecordsToCSVFile(filename=filename)
            connection.send("Success")

        connection.close()
        thread.exit_thread()

    #Server
    def run(self):
        print 'Server begins running...'
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock.bind((self.host, self.port))
        #server_ip = '192.168.1.174'
        #server_ip = '10.13.14.176'
        #server_ip = '10.13.25.118'
        #server_ip = '10.13.23.176'
        #server_ip = '10.13.22.184'
        #server_ip = '192.168.8.100'
        server_ip = '43.240.98.63'
        sock.bind((server_ip, 8800))
        sock.listen(10)
        print "Server begins listening..."
        try:
            while True:
                connection, address = sock.accept()
                thread.start_new_thread(self.child_connection, (sock, connection))
        except KeyboardInterrupt:
            sock.close()
            print 'Server stops running.'
            sys.exit(0)



def readCommand(argv):
    from optparse import OptionParser
    usageStr = """
    VERSION:    python 2.7
    USAGE:      python psypadServer.py <options>
    OPTIONS:    --dbhost    IP address of the database, default is 'localhost'
                --dbuser    the user of the database, default is 'root'
                --dbpwd     the password of the database
                --dbname    the name of the database, default is 'psypad'
                --prefix    the valid prefix of user's rego, default is 'ts', case insensitive

    EXAMPLES:   (1) python psypadServer.py
                    - starts server by using default configurations
                (2) python psypadServer.py --dbhost <db ip address> --dbuser <db user> --dbpwd <db password> --dbname <db name> --prefix <valid prefix>
                    - starts server by using specified configurations
    """
    parser = OptionParser(usageStr)
    parser.add_option('--dbhost', dest='host', default='localhost')
    parser.add_option('--dbuser', dest='db_user', default='root')
    parser.add_option('--dbpwd', dest='db_password', default='1234')
    parser.add_option('--dbname', dest='schema_name',  default='psypad')
    parser.add_option('--prefix', dest='validPrefix', default="ts")

    options, other_junk = parser.parse_args(argv)
    if len(other_junk) != 0:
        raise Exception('Command line input not understood: ' + str(other_junk))
    args = dict()
    args['host'] = options.host
    args['db_user'] = options.db_user
    args['db_password'] = options.db_password
    args['schema_name'] = options.schema_name
    args['validPrefix'] = options.validPrefix
    return args

# def mainProcess(host, db_user, db_password, schema_name, validPrefix):
#     aServer = psypadServer(host=host, db_user=db_user, db_password=db_password, schema_name=schema_name,validPrefix=validPrefix)
#     aServer.run()
#     sys.exit(0)

if __name__ == '__main__':
    args = readCommand( sys.argv[1:] )
    aServer = psypadServer(**args)
    aServer.run()
    pass