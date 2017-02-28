import ast
import pprint

def get_dict_from_string(string):
    dict_str = None
    try:
        dict_str = ast.literal_eval(string)
    except Exception as e:
        print e
    return dict_str

def pretty(d, indent=1):
   for key, value in d.iteritems():
      print '\t' * indent + str(key) +":"
      if isinstance(value, dict):
         pretty(value, indent+1)
      else:
         print '\t' * (indent+1) + str(value)

def print_dict(context, dictionary):
    print "-" * len(context)
    print context , ":"
    print "-" * len(context)
    print "{"
    pretty(dictionary)
    print "}"

def print_trancsation_message(msg):
    liner = "*"
    message = "*" + " "*10 + "  " + msg + "  " + " "*10 + "*"
    print liner * len(message)
    print message
    print liner * len(message)

def print_line():
    liner = "-"
    print liner * 64

if __name__ == '__main__':
    print_trancsation_message("Message 1 form client")
