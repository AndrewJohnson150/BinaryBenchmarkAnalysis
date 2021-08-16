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
require(foreign)
require(ggplot2)
require(MASS)
library(pscl)
library(car)

data = read.csv("Data/DataWithDomainNoDependency.csv")

#Turn compiler into a binary factor
for (i in 1:nrow(data)) {
  if (data[i,"compiler"]!="Unk") 
    data[i,"compiler"] <- "GCC"
}

data[,"compiler"] <- as.factor(data[,"compiler"])
data[,"static"] <- as.factor(data[,"static"])
data[,"domain"] <- as.factor(data[,"domain"])
 
summary(m1 <- glm.nb(cwe_checker ~ size +static+domain+compiler, data = data))
Anova(m1)

summary(m2 <- zeroinfl(cve_bin_tool ~ scale(size) + static+domain+compiler|scale(size) + static+domain+compiler, data = data,dist = "negbin"))
Anova(m2)

summary(m3 <- zeroinfl(yara_rules ~ scale(size) + static+domain+compiler|scale(size) + static+domain+compiler, data = data,dist = "negbin"))
Anova(m3)

#Interpretation
## Exponentiated coefficients, cwe_checker
expCoefm1 <- exp(coef((m1)))
expCoefm1

## Exponentiated coefficients, cve-bin-tool
expCoefm2 <- exp(coef((m2)))
expCoefm2 <- matrix(expCoefm2,ncol=2)
rownames(expCoefm2) <- names(coef(m1))
colnames(expCoefm2) <- c("Count_model","Zero_inflation_model")
expCoefm2

## Exponentiated coefficients, yara-rules
expCoefm3 <- exp(coef((m3)))
expCoefm3 <- matrix(expCoefm3,ncol=2)
rownames(expCoefm3) <- names(coef(m1))
colnames(expCoefm3) <- c("Count_model","Zero_inflation_model")
expCoefm3


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

###Yara-Rules
p1<-ggplot(data=data,aes(x=compiler,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=data,aes(x=static,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=data,aes(x=domain,y=yara_rules)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p4<-ggplot(data=data,aes(x=size,y=yara_rules)) +
  geom_point()+stat_cor(method="spearman")
grid.arrange(p1, p2, p3, p4, ncol=2,nrow=2, top = textGrob("Yara Rules Output Compared to Factors",gp=gpar(fontsize=20,font=1)))

### CVE-Bin-Tool
p1<-ggplot(data=data,aes(x=compiler,y=cve_bin_tool)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p2<-ggplot(data=data,aes(x=static,y=cve_bin_tool)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p3<-ggplot(data=data,aes(x=domain,y=cve_bin_tool)) +
  geom_boxplot() + stat_compare_means(method = "kruskal.test")
p4<-ggplot(data=data,aes(x=size,y=cve_bin_tool)) +
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

