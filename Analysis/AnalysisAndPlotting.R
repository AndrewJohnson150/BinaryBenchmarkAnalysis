library(readr)
library(tidyverse)
library(ggplot2)
library(GGally)
library(ggfortify)
library(FactoMineR)
library(factoextra)
library(ggpubr)
library(rstatix)
library(quantreg)
library(gridExtra)

data = read.csv("Data.csv")
data[,"compiler"] <- as.factor(data[,"compiler"])
data[,"static"] <- as.factor(data[,"static"])

###CWE_Checker
p1<-ggplot(data=data,aes(x=compiler,y=cwe_checker)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=data,aes(x=static,y=cwe_checker)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=data,aes(x=size,y=cwe_checker)) +
  geom_point()+stat_cor(method="spearman")
grid.arrange(p1, p2, p3, ncol=3)

  ###Yara-Rules
p1<-ggplot(data=data,aes(x=compiler,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=data,aes(x=static,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=data,aes(x=size,y=yara_rules)) +
  geom_point()+stat_cor(method="spearman")
grid.arrange(p1, p2, p3, ncol=3)

### CVE-Bin-Tool
p1<-ggplot(data=data,aes(x=compiler,y=cve_bin_tool)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=data,aes(x=static,y=cve_bin_tool)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=data,aes(x=size,y=cve_bin_tool)) +
  geom_point()+stat_cor(method="spearman")
grid.arrange(p1, p2, p3, ncol=3)

#factor histograms
p1<- ggplot(data=data,aes(x=compiler)) + geom_bar()
p2<- ggplot(data=data,aes(x=static)) + geom_bar()
p3<- ggplot(data=data,aes(x=size)) + geom_histogram(bins=50)
grid.arrange(p1, p2, p3, ncol=3)

#Size compared to compiler, static with KW test
p1 <- ggplot(data=data,aes(x=compiler,y=size)) + geom_boxplot()+ stat_compare_means(method = "kruskal.test")
p2 <- ggplot(data=data,aes(x=static,y=size)) + geom_boxplot()+ stat_compare_means(method = "kruskal.test")
grid.arrange(p1, p2, ncol=2)


###Original tool histograms compared to log(data)
p1<- ggplot(data=data,aes(x=cwe_checker)) + geom_histogram(bins=50)
p2<- ggplot(data=data,aes(x=cve_bin_tool)) + geom_histogram(bins=50)
p3<- ggplot(data=data,aes(x=yara_rules)) + geom_histogram(bins=50)
p4<- ggplot(data=data,aes(x=log(cwe_checker+1))) + geom_histogram(bins=50)
p5<- ggplot(data=data,aes(x=log(cve_bin_tool+1))) + geom_histogram(bins=50)
p6<- ggplot(data=data,aes(x=log(yara_rules+1))) + geom_histogram(bins=50)
grid.arrange(p1, p2, p3,p4,p5,p6, ncol=3,nrow=2) 

p1<- ggplot(data=data,aes(x=cwe_checker)) + geom_histogram(bins=50)
p2<- ggplot(data=data,aes(x=cve_bin_tool)) + geom_histogram(bins=50)
p3<- ggplot(data=data,aes(x=yara_rules)) + geom_histogram(bins=50)
p4<- ggplot(data=data,aes(x=(cwe_checker+1))) + geom_histogram(bins=50)
p5<- ggplot(data=data,aes(x=(cve_bin_tool^2))) + geom_histogram(bins=50)
p6<- ggplot(data=data,aes(x=(yara_rules^2))) + geom_histogram(bins=50)
grid.arrange(p1, p2, p3,p4,p5,p6, ncol=3,nrow=2) 
