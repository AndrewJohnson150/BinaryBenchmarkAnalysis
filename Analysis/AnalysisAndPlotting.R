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
library(grid)
library(gridExtra)
library(foreign)
library(ggplot2)
library(MASS)
library(pscl)
library(car)
library(effects)

data = read.csv("Data/DataWithDomainNoDependency.csv")

#Turn compiler into a binary factor
for (i in 1:nrow(data)) {
  if (data[i,"compiler"]!="Unk") 
    data[i,"compiler"] <- "GCC"
}

data[,"compiler"] <- as.factor(data[,"compiler"])
data[,"static"] <- as.factor(data[,"static"])
data[,"domain"] <- as.factor(data[,"domain"])
data[,"cbtFindings"]<- ifelse(data[,"cve_bin_tool"]==0,0,1)
data[,"yrFindings"]<- ifelse(data[,"yara_rules"]==0,0,1)

data[,"cbtFindings"]<- as.factor(data[,"cbtFindings"])
data[,"yrFindings"]<- as.factor(data[,"yrFindings"])


#factor histograms
p1<- ggplot(data=data,aes(x=compiler)) + geom_bar()
p2<- ggplot(data=data,aes(x=static)) + geom_bar()
p3<- ggplot(data=data,aes(x=size)) + geom_histogram(bins=50)
p4<- ggplot(data=data,aes(x=domain)) + geom_bar()
grid.arrange(p1, p2, p3,p4, ncol=2,nrow=2, top = textGrob("Factor Distributions",gp=gpar(fontsize=20,font=1)))

###CWE_Checker
p1<-ggplot(data=data,aes(x=compiler,y=cwe_checker)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=data,aes(x=static,y=cwe_checker)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=data,aes(x=domain,y=cwe_checker)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p4<-ggplot(data=data,aes(x=size,y=cwe_checker)) +
  geom_point()+stat_cor(method="spearman")
grid.arrange(p1, p2, p3, p4, ncol=2,nrow=2, top = textGrob("CWE_Checker Output Compared to Factors",gp=gpar(fontsize=20,font=1)))

###Yara-Rules non-zeros
yrData <- data[which(data$yrFindings==1),]
p1<-ggplot(data=yrData,aes(x=compiler,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=yrData,aes(x=static,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=yrData,aes(x=domain,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p4<-ggplot(data=yrData,aes(x=scale(size),y=yara_rules)) +
  geom_point()+stat_cor(method="spearman")
grid.arrange(p1, p2, p3, p4, ncol=2,nrow=2, top = textGrob("Non-Zero Yara Rules Output Compared to Factors",gp=gpar(fontsize=20,font=1)))

###Yara-Rules zeros
p1<-ggplot(data=data,aes(x=compiler,fill=yrFindings)) +
  geom_bar() 
p2<-ggplot(data=data,aes(x=static,fill=yrFindings)) +
  geom_bar() 
p3<-ggplot(data=data,aes(x=domain,fill=yrFindings)) +
  geom_bar() 
p4<-ggplot(data=data,aes(x=scale(size),y=yrFindings)) +
  geom_jitter()
grid.arrange(p1, p2, p3, p4, ncol=2,nrow=2, top = textGrob("Zero vs Non-Zero Yara Rules Output Compared to Factors",gp=gpar(fontsize=20,font=1)))

###Yara-Rules
p1<-ggplot(data=data,aes(x=compiler,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=data,aes(x=static,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=data,aes(x=domain,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p4<-ggplot(data=data,aes(x=scale(size),y=yara_rules)) +
  geom_point()+stat_cor(method="spearman")
grid.arrange(p1, p2, p3, p4, ncol=2,nrow=2, top = textGrob("Yara Rules Output Compared to Factors",gp=gpar(fontsize=20,font=1)))



### CVE-Bin-Tool non-zeros
cbtFindings <- data[which(data$cbtFindings==1),]
p1<-ggplot(data=cbtFindings,aes(x=compiler,y=cve_bin_tool)) +
  geom_boxplot() 
p2<-ggplot(data=cbtFindings,aes(x=static,y=cve_bin_tool)) +
  geom_boxplot() 
p3<-ggplot(data=cbtFindings,aes(x=domain,y=cve_bin_tool)) +
  geom_boxplot() 
p4<-ggplot(data=cbtFindings,aes(x=scale(size),y=cve_bin_tool)) +
  geom_point()
grid.arrange(p1, p2, p3, p4, ncol=2,nrow=2, top = textGrob("Non-Zero CVE-Bin-Tool Output Compared to Factors",gp=gpar(fontsize=20,font=1)))

### CVE-Bin-Tool zeros
p1<-ggplot(data=data,aes(x=compiler,fill=cbtFindings)) +
  geom_bar() 
p2<-ggplot(data=data,aes(x=static,fill=cbtFindings)) +
  geom_bar() 
p3<-ggplot(data=data,aes(x=domain,fill=cbtFindings)) +
  geom_bar() 
p4<-ggplot(data=data,aes(x=scale(size),y=cbtFindings)) +
  geom_jitter()
grid.arrange(p1, p2, p3, p4, ncol=2,nrow=2, top = textGrob("Zero vs Non-Zero CVE-Bin-Tool Output Compared to Factors",gp=gpar(fontsize=20,font=1)))

### CVE-Bin-Tool
p1<-ggplot(data=data,aes(x=compiler,y=cve_bin_tool)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=data,aes(x=static,y=cve_bin_tool)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=data,aes(x=domain,y=cve_bin_tool)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p4<-ggplot(data=data,aes(x=scale(size),y=cve_bin_tool)) +
  geom_point()+stat_cor(method="spearman")
grid.arrange(p1, p2, p3, p4, ncol=2,nrow=2, top = textGrob("CVE-Bin-Tool Output Compared to Factors",gp=gpar(fontsize=20,font=1)))


#Size compared to compiler, static, and domain with KW test
p1 <- ggplot(data=data,aes(x=compiler,y=size)) + geom_boxplot()+ stat_compare_means(method = "kruskal.test")
p2 <- ggplot(data=data,aes(x=static,y=size)) + geom_boxplot()+ stat_compare_means(method = "kruskal.test")
p3 <- ggplot(data=data,aes(x=domain,y=size)) + geom_boxplot()+ stat_compare_means(method = "kruskal.test")
grid.arrange(p1, p2, p3, ncol=3, top = textGrob("Size Compared to Other Factors",gp=gpar(fontsize=20,font=1)))

###Tool finding histograms
p1<- ggplot(data=data,aes(x=cwe_checker)) + geom_histogram(bins=50)
p2<- ggplot(data=data,aes(x=cve_bin_tool)) + geom_histogram(bins=50)
p3<- ggplot(data=data,aes(x=yara_rules)) + geom_histogram(bins=50)
grid.arrange(p1, p2, p3, ncol=3, top = textGrob("Tool Output Histograms",gp=gpar(fontsize=20,font=1)))


###Original tool histograms compared to log(data)
p1<- ggplot(data=data,aes(x=cwe_checker)) + geom_histogram(bins=50)
p2<- ggplot(data=data,aes(x=cve_bin_tool)) + geom_histogram(bins=50)
p3<- ggplot(data=data,aes(x=yara_rules)) + geom_histogram(bins=50)
p4<- ggplot(data=data,aes(x=log(cwe_checker+1))) + geom_histogram(bins=50)
p5<- ggplot(data=data,aes(x=log(cve_bin_tool+1))) + geom_histogram(bins=50)
p6<- ggplot(data=data,aes(x=log(yara_rules+1))) + geom_histogram(bins=50)
grid.arrange(p1, p2, p3,p4,p5,p6, ncol=3,nrow=2, top = textGrob("Tool Output Compared to Log(Tool Output)",gp=gpar(fontsize=20,font=1)))

