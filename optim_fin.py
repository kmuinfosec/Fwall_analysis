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

BASE_PATH= 'Wins_FIREWALL/results' #결과물 경로

def memory_usage(message: str = 'debug'):  #메모리 사용량
    # current process RAM usage
    p = psutil.Process()
    rss = p.memory_info().rss / 2 ** 20 # Bytes to MB
    print(f"[{message}] memory usage: {rss: 10.5f} MB")


class topk_delta():
    def __init__(self,path,w,k,d,ugr=False) -> None:
        self.ugr = ugr
        if self.ugr: #UGR데이터 셋 사용할때 사용하는 컬럼
            self.columns = ['Rdate','duration','src_ip','dst_ip','src_port','dst_port','proto','flag','forwarding status','ToS','packets','bytes','label']
        else: #윈스 컬럼
            self.columns = ['Rdate','sender_type','Ip','group_id','device_type','ckc','sensor_id','Stime','Etime','src_ip','dst_ip','Proto','src_port','dst_port','Action','signiture','highlight','priority','Cnt','src_country','dst_country','device_id','Node','category','minor','Flag','msg','pool_id','pool_group_id','cve_code','data_type','is_profile','Profile_log_id_list','Profile_id','Profile_name','Ai_flag','Opt0','Opt1','Opt2','Opt3','Opt4','Opt5','Opt6','Opt7','Opt8','Opt9','Opt10','Opt11']
        
        self.paths = glob(path,recursive=True) #방화벽 데이터셋 경로

        self.arg_ds = [ # 만들 테이블의 key들 hh: heavy hitter, hdh: heavy distinct hitter

            'hh: dst_port',
            'hh: src_ip||dst_port',
            'hh: src_ip||dst_country',
            'hh: dst_country',
            'hh: dst_ip',
            'hh: src_ip',
            'hh: src_ip||dst_ip',
            'hdh: dst_ip||src_country',
            'hdh: src_ip||dst_port',
            'hdh: src_ip||dst_ip',
            'hdh: dst_ip||src_ip'

            ]
        self.d=d #테이블의 기간 
        self.table=[]
        self.k = k #top-k의 k
        self.w = w # 테이블을 합칠 기간(훈련기간)

        self.fromiso  = datetime.datetime.fromisoformat

    def create_table(self):  #빈 테이블 작성(d)
        arg_d = dict()
        for i in self.arg_ds:
            if 'hh' in i:
                ccounter = collections.Counter()
                arg_d[i] = ccounter
            else:
                a= dict()
                arg_d[i]= a
        return arg_d

    def fname2time(self, path): #파일 이름을 isoformat 시간으로
        tmp = path.split('\\')[-1].split('.')[0].split('-')[:2]
        y=tmp[0][:4]
        m=tmp[0][4:6]
        d=tmp[0][6:]
        h=tmp[1]
        return f"{y}-{m}-{d} {h}:00:00"
    
    def path_window(self): #파일경로를 시간대별로 정리
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
        arg_d = self.create_table()
        for i in tqdm(data):
            with open(i,'r',encoding='utf-8') as f:
                while True:
                    lines = f.readlines(10000)
                    if not lines:
                        break
                    else:
                        for l in lines:
                            tmp = dict(zip(self.columns,l.split('\t')))
                            for key in arg_d:
                                keys = key.split(' ')
                                if 'hh' in keys[0]:
                                    keys = keys[1]
                                    if '||' in keys:
                                        keys = keys.split('||')
                                        val = '||'.join([tmp[i] for i in keys])
                                        arg_d[key].update({val})
                                    else:   
                                        arg_d[key].update({tmp[keys]})
                                else:
                                    keys = keys[1].split('||')

                                    if tmp[keys[0]] not in arg_d[key]:
                                        a={tmp[keys[1]]}
                                        arg_d[key][tmp[keys[0]]] = a
                                    else:
                                        arg_d[key][tmp[keys[0]]].update({tmp[keys[1]]})
        return arg_d


    def k_extract(self): # top-k의 key값만 가져옴 
        self.wls = []

        for tables in self.t:
            wl = self.mk_day_set()
            for idx,key in enumerate(tables):
                if type(tables[key])!=type({}):
                    for i in (map(lambda x :x[0] ,tables[key].most_common(self.k))):
                        wl[idx].add(i)
                else:
                    tmp = collections.Counter(dict(list(map(lambda x:(x[0], len(x[1])), tables[key].items()))))
                    for i in (map(lambda x :x[0] ,tmp.most_common(self.k))):
                        wl[idx].add(i)
            self.wls.append(wl)

    def mk_day_set(self): # 빈 셋트 만듬
        wls=[]
        for i in range(len(self.arg_ds)):
            wls.append(set())
        return wls

    def set_diff(self): # 차집합
        self.k_extract()
        self.diff_output= []
        i=1
        for s_day in range(self.d):
            l = self.table_diff(0,s_day)
            self.diff_output.append(l)
            
        for s_day in range(0,len(self.wls)-self.d):
            l = self.table_diff(s_day,self.d)
            self.diff_output.append(l)

    
    def table_diff(self,s_day,d): #테이블간 차집합
        d_set = self.mk_day_set()
        l=[]
        for day in range(s_day,s_day+d):
            for i in range(len(d_set)):
                da =self.wls[day][i]
                d_set[i] = set.union(d_set[i],da)

        for before,now in zip(d_set,self.wls[s_day+d]):
            l.append(now.difference(before))
        return l

    def run(self): # 실행
        l = self.window()
        reg = re.compile('[\/:*?\"<>|]')
        self.t = []
        cache_path=f'{BASE_PATH}/cache/'
        if not os.path.exists(cache_path):
            os.mkdir(cache_path)
        for p in l:
            start= self.fname2time(p[0])
            end = self.fname2time(p[-1])
            fname = f'{start}-{end}'
            fname = reg.sub('',fname)
            if not os.path.exists(f'{cache_path+fname}.pkl'): #날짜별로 캐시 저장
                tables = self.count_topk(p)
                with open(f'{cache_path+fname}.pkl','wb') as f:
                    pickle.dump(tables,f)
            else:
                with open(f'{cache_path+fname}.pkl','rb') as f:
                    tables = pickle.load(f)   
            self.t.append(tables)
        self.set_diff()

    def transpose(self,diff):
        ls=[]
        key_len = len(self.arg_ds)
        for day,d in enumerate(diff):
            for idx,c in enumerate(d):
                if day==0:
                    ls.append([c])
                else:
                    ls[idx].append(c)
        return ls

    def graph(self,path)->None: #결과 그래프로 이미지 저장
        l = self.transpose(self.diff_output)
        if not os.path.exists(path):
            os.mkdir(path)
        reg = re.compile('[\/:*?\"<>|]')
        for i,t in zip(l,self.arg_ds):
            plt.figure(figsize=(12,6))
            plt.ylim(top=self.k)
            plt.yticks(fontsize=20)
            plt.xticks(np.arange(len(i))+1,fontsize=20)
            plt.bar(np.arange(len(i))+1, list(map(lambda x: len(x),i)))
            plt.title(label=t,fontsize=28)
            t = reg.sub(' ',t)
            plt.savefig(f'{path}/{t}.png')

    def raw(self,day,col)->list: #원하는 날의 컬럼 key:value 리스트로 반환

        for idx,c in enumerate(self.arg_ds):
            if c == col:
                col_idx = idx
        
        return [(i,self.t[day][col][i]) for i in self.diff_output[day][col_idx]]
        
        # if col == 'all':
        #     return self.t[day]
        # # return self.t[day][col]




if __name__ == '__main__':
    memory_usage()
    a = topk_delta(r'Wins_FIREWALL\data\202106\FWall',24,30,7)
    a.run()
    a.graph('Wins_FIREWALL/results/graph')
    print(a.raw(0,'hh: src_ip'))
    memory_usage()