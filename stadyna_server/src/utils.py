 # Copyright (C) 2013-2015 StaDynA
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #      http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #
 # Author(s): Yury Zhauniarovich
 
from logconfig import logger

def clsToDalvikCls(className):
    logger.debug("Converting [%s] class name to Dalvik format class name..." % className)
    res = None
    if className:
        res = "L%s" % className
        res = res.replace('.', '/')
    logger.debug("Dalvik format of the class name [%s] is [%s]!" % (className, res))
    return res


def transformStack(stack):
    logger.debug("Transforming stack data into internal representation...")
    transformedStack = []
    for i in stack:
        t = tuple(str(v.strip()) for v in i.split(","))
#         t = tuple(v.strip() for v in i.split(","))
        transformedStack.append(t)
    logger.debug("Stack transformed successfully!")
    return transformedStack

def convertPathToSeccon((cls, method, proto)):
    protoNew = proto.replace(" ", "")
    return (cls, method, protoNew)
    