import os
from glob import glob
from tqdm import tqdm
import pickle
import psutil
import collections
import datetime
import re
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def memory_usage(message: str = 'debug'):  #메모리 사용량
    # current process RAM usage
    p = psutil.Process()
    rss = p.memory_info().rss / 2 ** 20 # Bytes to MB
    print(f"[{message}] memory usage: {rss: 10.5f} MB")


class topk_delta():
    def __init__(self,data_path,res_path,w,k,d,ugr=False,use_cache=False,recursive = False) :
        if (res_path[-1]=='/') or (res_path[-1]=='\\'):
            self.res_path = res_path[:-1]
        else:
            self.res_path= res_path #결과물 경로
        self.use_cache = use_cache
        if not os.path.exists(res_path):
            os.mkdir(self.res_path)
        self.ugr = ugr
        if self.ugr: #UGR데이터 셋 사용할때 사용하는 컬럼 윈스에선 사용 안함
            self.columns = ['Rdate','duration','src_ip','dst_ip','src_port','dst_port','proto','flag','forwarding status','ToS','packets','bytes','label']
        else: #윈스 컬럼
            self.columns = ['Rdate','sender_type','Ip','group_id','device_type','ckc','sensor_id','Stime','Etime','src_ip','dst_ip','Proto','src_port','dst_port','Action','signiture','highlight','priority','Cnt','src_country','dst_country','device_id','Node','category','minor','Flag','msg','pool_id','pool_group_id','cve_code','data_type','is_profile','Profile_log_id_list','Profile_id','Profile_name','Ai_flag','Opt0','Opt1','Opt2','Opt3','Opt4','Opt5','Opt6','Opt7','Opt8','Opt9','Opt10','Opt11']
        
        self.paths = glob(data_path,recursive=recursive) #방화벽 데이터셋 경로

        self.keys = [ # 만들 테이블의 key들 hh: heavy hitter, hdh: heavy distinct hitter

                        # hh에서 || -> concat     ex)src_ip||dst_port -> 192.168.0.1||8.8.8.8 이 키값이 되어서 카운트함

                        # hdh에서 ex) dst_ip||src_country -> dst_ip:{src_country} 앞의 키를 키값으로 주고 뒤의 키의 카디널리티를 값으로 줌

            'hh: dst_port',
            'hh: src_ip||dst_port',
            'hh: src_ip||dst_country',
            'hh: dst_country',
            'hh: dst_ip',
            'hh: src_ip',
            'hh: src_ip||dst_ip',
            'hdh: src_ip||dst_country',
            'hdh: src_ip||dst_port',
            'hdh: src_ip||dst_ip',
            'hh: src_port||dst_port'

            ]


        self.d=d #테이블의 기간 

        self.table=[]

        self.k = k #top-k의 k

        self.w = w # 테이블을 합칠 기간(훈련기간)

        self.fromiso  = datetime.datetime.fromisoformat # 데이트타임 형식으로 바꿔주는 함수

    def create_table(self):  #분석한 키들을 파싱해서 빈 테이블 작성(d)
        tables = dict()
        for i in self.keys:
            if 'hh' in i:
                ccounter = collections.Counter()
                tables[i] = ccounter
            else:
                a= dict()
                tables[i]= a
        return tables

    def fname2time(self, path): #파일 이름을 파싱해서 isoformat 시간으로
        tmp = path.split('\\')[-1].split('.')[0].split('-')[:2]
        y=tmp[0][:4]
        m=tmp[0][4:6]
        d=tmp[0][6:]
        h=tmp[1]
        return f"{y}-{m}-{d} {h}:00:00"
    
    def path_window(self): #파일경로를 시간대별로 정리 key:value = 시간:경로
        self.w_path= dict()
        for p in self.paths:
            a= self.fromiso(self.fname2time(p))
            if a not in self.w_path:
                self.w_path[a]=[p]
            else:
                self.w_path.get(a).append(p)



    def window(self): #시간대별 경로를 window단위로 묶음
        self.path_window()
        keys = sorted(self.w_path.keys())
        start = keys[0]
        end = start + datetime.timedelta(hours=self.w)
        l=[]
        p=[]
        for i in keys:
            if i < end:
                p+=self.w_path[i]
            else:
                l.append(p)
                p=[]
                end += datetime.timedelta(hours=self.w)

        return l


    def count_topk(self,data): # 파일을 읽어서 전체 카운트
        tables = self.create_table()
        for i in tqdm(data):
            with open(i,'r',encoding='utf-8') as f:
                while True: 
                    lines = f.readlines(10000) # 10000줄만 읽기
                    if not lines: #파일 전체 읽으면 반복문 탈출
                        break
                    else:
                        for l in lines:
                            tmp = dict(zip(self.columns,l.split('\t'))) #wins 로그가 tsv형식이여서 탭으로 끊고 컬럼이름으로 임시 딕셔너리 만듬
                            for key in tables: #빈테이블의 키 파싱
                                keys = key.split(' ')
                                if 'hh' in keys[0]: # heavy hitter의 경우 counter 함수를 이용해서 카운팅
                                    keys = keys[1]
                                    if '||' in keys:
                                        keys = keys.split('||')
                                        val = '||'.join([tmp[i] for i in keys])
                                        tables[key].update({val})
                                    else:   
                                        tables[key].update({tmp[keys]})
                                else: # heavy distinct hitter 의 경우 딕셔너리에 set을 이용해서 카디널리티 카운트
                                    keys = keys[1].split('||')

                                    if tmp[keys[0]] not in tables[key]:
                                        a={tmp[keys[1]]}
                                        tables[key][tmp[keys[0]]] = a
                                    else:
                                        tables[key][tmp[keys[0]]].update({tmp[keys[1]]})
        return tables


    def k_extract(self): # top-k의 key값만 가져옴 
        self.wls = []

        for tables in self.t: # 전체테이블 반복
            wl = self.mk_day_set() # white list를 담을 빈 셋트

            for idx,key in enumerate(tables):
                if type(tables[key])!=type({}): # heavy hitter
                    for i in (map(lambda x :x[0] ,tables[key].most_common(self.k))): # top-k의 key값만 가져옴 
                        wl[idx].add(i)

                else: # heavy distinct hitter
                    tmp = collections.Counter(dict(list(map(lambda x:(x[0], len(x[1])), tables[key].items()))))
                    for i in (map(lambda x :x[0] ,tmp.most_common(self.k))):
                        wl[idx].add(i)
            self.wls.append(wl)

    def mk_day_set(self): # 빈 셋트 만듬
        wls=[]
        for i in range(len(self.keys)):
            wls.append(set())
        return wls

    def set_diff(self): # 차집합
        self.k_extract()
        self.diff_output= []
        i=1
        for s_day in range(self.d): # bootstrap 기간이 되기 전까지 
            l = self.table_diff(0,s_day)
            self.diff_output.append(l)
            
        for s_day in range(0,len(self.wls)-self.d): # bootstrap 이후
            l = self.table_diff(s_day,self.d)
            self.diff_output.append(l)

    
    def table_diff(self,s_day,d): #테이블간 차집합
        d_set = self.mk_day_set()
        l=[]
        for day in range(s_day,s_day+d):
            for i in range(len(d_set)):
                da =self.wls[day][i]
                d_set[i] = set.union(d_set[i],da)
        # print(self.wls)
        # quit()
        for before,now in zip(d_set,self.wls[s_day+d]):
            l.append(now.difference(before))
        return l

    def run(self): # 실행
        self.l = self.window() # 윈도우 시간별로 경로 묶기

        reg = re.compile('[\/:*?\"<>|]')
        
        self.t = []
        
        cache_path=f'{self.res_path}/cache/' # 캐시 경로

        if not self.use_cache:
            for p in self.l:
                start= self.fname2time(p[0]) #window내의 첫 파일 이름 파싱
                end = self.fname2time(p[-1]) #window내의 마지막 파일 이름 파싱

                fname = f'{start}-{end}' # 캐시 파일이름 
                fname = reg.sub('',fname) # 특수문자 제거
                tables = self.count_topk(p)
                self.t.append(tables)
        
        else:
            if not os.path.exists(cache_path):
                os.mkdir(cache_path)
            for p in self.l:
                start= self.fname2time(p[0]) #window내의 첫 파일 이름 파싱
                end = self.fname2time(p[-1]) #window내의 마지막 파일 이름 파싱

                fname = f'{start}-{end}' # 캐시 파일이름 
                fname = reg.sub('',fname) # 특수문자 제거

                if not os.path.exists(f'{cache_path+fname}.pkl'): #캐시가 없으면 날짜별로 캐시 저장
                    tables = self.count_topk(p)

                    with open(f'{cache_path+fname}.pkl','wb') as f:
                        pickle.dump(tables,f)
                else: # 캐시 존재시 캐시 불러오기
                    with open(f'{cache_path+fname}.pkl','rb') as f:
                        tables = pickle.load(f)   
                self.t.append(tables)

        self.set_diff()

        self.t_table = self.transpose(self.diff_output)

    def transpose(self,diff): # [1일(hh: src_ip, hdh:src_ip, ... ),2일(...), ...] - >[hh:src_ip(1일,2일,3일....), hdh:src_ip(1일,2일,3일...),....]
        ls=[]
        key_len = len(self.keys)
        for day,d in enumerate(diff):
            for idx,c in enumerate(d):
                if day==0:
                    ls.append([c])
                else:
                    ls[idx].append(c)
        return ls

    def graph(self,path)->None: #결과 그래프로 이미지 저장
        path = f'{self.res_path}'
        if not os.path.exists(path):
            os.mkdir(path)
        reg = re.compile('[\/:*?\"<>|]')
        for i,t in zip(self.t_table,self.keys):
            plt.figure(figsize=(12,6))
            plt.ylim(top=self.k)
            plt.yticks(fontsize=20)
            plt.xticks(np.arange(len(i))+1,fontsize=20)
            plt.bar(np.arange(len(i))+1, list(map(lambda x: len(x),i)))
            plt.title(label=t,fontsize=28)
            t = reg.sub(' ',t)
            plt.savefig(f'{path}/{t}.png')

    def raw(self,day=0,col=0): #원하는 날의 컬럼 key:value 리스트로 반환

        for idx,c in enumerate(self.keys):
            if c == col:
                col_idx = idx
        if 'hdh' in col:
            raw = [(i,len(self.t[day][col][i])) for i in self.diff_output[day][col_idx]]
        else:
            raw = [(i,self.t[day][col][i]) for i in self.diff_output[day][col_idx]]
        raw = sorted(raw,key = lambda x: x[1],reverse=True)

        return [(f"{i[0]}: {i[1]}") for i in raw]
    
    # def to_csv(self,show_value=False): # 결과 csv로 저장
    #     l = self.transpose(self.diff_output)
    #     reg = re.compile('[\/:*?\"<>|]')

    #     s = self.fname2time(self.l[0][0])
    #     e = self.fname2time(self.l[-1][-1])
    #     if show_value:
    #         with open(f'{self.res_path}/report_{reg.sub(" " ,"__".join((s,e)))}.csv', 'w', encoding='utf-8') as f:
    #             f.write('day,subject,count,keys:values\n')

    #             for s_idx, sub in enumerate(l):
    #                 subject = self.keys[s_idx]
    #                 if 'hdh' in subject:
    #                     for day, i in enumerate(sub):
    #                         f.write(f"{day+1},{subject},{len(i)},{'   '.join(self.raw(day,subject))}")
    #                         f.write('\n')
    #                 else:
    #                     for day, i in enumerate(sub):
    #                         raw = self.raw(day,subject)
    #                         raw = sorted(raw,key=lambda x: x[1])
    #                         f.write(f"{day+1},{subject},{len(i)},{'   '.join(self.raw(day,subject))}")
    #                         f.write('\n')
            
        # else:
        #     with open(f'{self.res_path}/report_{reg.sub(" " ,"__".join((s,e)))}.csv', 'w', encoding='utf-8') as f:
        #         f.write('day, subject, count, keys:values\n')
        #         for s_idx, sub in enumerate(l):
        #             subject = self.keys[s_idx]
        #             for day, i in enumerate(sub):
        #                 f.write(f"{day+1},{subject},{len(i)},{'    '.join(i)}")
        #                 f.write('\n')
    
    def to_csv(self,show_value=False): # 결과 csv로 저장
        l = self.diff_output
        reg = re.compile('[\/:*?\"<>|]')

        s = self.fname2time(self.l[0][0])
        e = self.fname2time(self.l[-1][-1])
        if show_value:
            with open(f'{self.res_path}/report_{reg.sub(" " ,"__".join((s,e)))}.csv', 'w', encoding='utf-8') as f:
                f.write('day,subject,count,keys:values\n')

                for day, d in enumerate(l):
                    for sub, i in enumerate(d):
                        subject = self.keys[sub]
                        if 'hdh' in subject:
                            f.write(f"{day+1},{subject},{len(i)},{'   '.join(self.raw(day,subject))}")
                            f.write('\n')   
                        else:
                            f.write(f"{day+1},{subject},{len(i)},{'   '.join(self.raw(day,subject))}")
                            f.write('\n')
                    f.write('\n')

            
        else:
            with open(f'{self.res_path}/report_{reg.sub(" " ,"__".join((s,e)))}.csv', 'w', encoding='utf-8') as f:
                f.write('day, subject, count, keys:values\n')
                for s_idx, sub in enumerate(l):
                    subject = self.keys[s_idx]
                    for day, i in enumerate(sub):
                        f.write(f"{day+1},{subject},{len(i)},{'    '.join(i)}")
                        f.write('\n')


if __name__ == '__main__':
    memory_usage()
    parameter = {'w':24,'k':30,'d':7}

    a = topk_delta(data_path = r'data\202106\FWall\*\*',recursive=True,res_path='./results',use_cache=True,**parameter)

    a.run()
    a.to_csv(show_value=True)
    a.graph('./graph')
    memory_usage()