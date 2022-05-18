#importing packages
import numpy as np 
import pandas as pd
import matplotlib.pyplot as plt

#create dataset
X= [[0.1,0.6],[0.15,0.71],[0.08,0.9],[0.16,0.85],[0.2,0.3],[0.25,0.5],[0.24,0.1],[0.3,0.2]]

#initial centroid poins
centers=np.array([[0.1,0.6],[0.3,0.2]])
print("Initial Centroids i.e Previous values of M1 and M2\n",centers)

#import kmean class
from sklearn.cluster import KMeans
model=KMeans(n_clusters=2,init=centers, n_init=1)
model.fit(X)

print("Labels",model.labels_)

#find P6 location
print("P6 belongs to cluster",model.labels_[5])

#using labels fnd the population around centriods
print("No. of population around cluster 2 :",np.count_nonzero(model.labels_==1))

#find new centroids
print("New Centroids i.e Updated Values of M1 and M2:\n",model.cluster_centers_)
