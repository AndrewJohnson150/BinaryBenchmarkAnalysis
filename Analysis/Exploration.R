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
library(car)

data = read.csv("Data/DataWithDomain.csv")
data[,"compiler"] <- as.factor(data[,"compiler"])
data[,"static"] <- as.factor(data[,"static"])
data[,"domain"] <- as.factor(data[,"domain"])

summary(data[,-which(names(data)=="binary")])

ggpairs(data[,!names(data) %in% c("binary","X")],aes(colour=static,alpha=0.5))
ggpairs(data[,!names(data) %in% c("binary","X")])


data[,c("size","static","compiler","cwe_checker","domain")] %>% ggpairs(upper = list(continuous = wrap("cor", method = "spearman")), diag = list(continuous = function(...) ggally_densityDiag(...) + theme(axis.text = element_blank(), axis.ticks = element_blank())))
data[,c("size","static","compiler","yara_rules","domain")]%>% ggpairs(upper = list(continuous = wrap("cor", method = "spearman")), diag = list(continuous = function(...) ggally_densityDiag(...) + theme(axis.text = element_blank(), axis.ticks = element_blank())))
data[,c("size","static","compiler","cve_bin_tool","domain")]%>% ggpairs(upper = list(continuous = wrap("cor", method = "spearman")), diag = list(continuous = function(...) ggally_densityDiag(...) + theme(axis.text = element_blank(), axis.ticks = element_blank())))

 ggplot(data=data,aes(x=compiler,y=cwe_checker)) +
  geom_boxplot()
ggplot(data=data,aes(x=compiler,y='cve_bin_tool')) +
  geom_boxplot()
ggplot(data=data,aes(x=compiler,y="yara_rules")) +
  geom_boxplot()



modelCVE <- lm((cve_bin_tool^2)~size+compiler+static,data=data)
par(mfrow=(c(2,2)))
plot(modelCVE)
(anova(modelCVE))


modelCWE <- lm(log(cwe_checker)~size+compiler+static+domain,data=data[-c(332),])
plot(modelCWE)
(anova(modelCWE))
summary(modelCWE)


modelYara <- lm(data[,"yara_rules"]~size*compiler*static,data=data)
(anova(modelYara))


#########Let's try logistic regression
data$BinCBT <- as.factor(with(data, ifelse(cve_bin_tool==0,0,1)))
data$BinYara <- as.factor(with(data, ifelse(yara_rules==0,0,1)))
ggplot(data=data,aes(x=BinCBT)) + geom_bar()
ggplot(data=data,aes(x=BinYara))+geom_bar()
#Remove outliers for assumptions of LR
modelCVE <- glm(BinCBT~size+compiler+static,data=data[-c(73,332,322),],family="binomial") 
summary(modelCVE)

modelYara <- glm(BinYara~size+compiler+static,data=data,family="binomial")
summary(modelYara)

#Check assumption for logistic regression

probabilities <- predict(modelCVE, type = "response")
predicted.classes <- ifelse(probabilities > 0.5, "pos", "neg")
newData <- data.frame(data$size, probabilities) %>%
  mutate(logit = log(probabilities/(1-probabilities)))

ggplot(newData, aes(logit, data.size))+
  geom_point(data.size = 0.5, alpha = 0.5) +
  geom_smooth(method = "loess") + 
  theme_bw() 


probabilities <- predict(modelYara, type = "response")
predicted.classes <- ifelse(probabilities > 0.5, "pos", "neg")
newData <- data.frame(data$size, probabilities) %>%
  mutate(logit = log(probabilities/(1-probabilities)))

ggplot(newData, aes(logit, data.size))+
  geom_point(data.size = 0.5, alpha = 0.5) +
  geom_smooth(method = "loess") + 
  theme_bw() 

plot(modelCVE, which = 4, id.n = 3)
plot(modelYara, which = 4, id.n = 3)
model.data <- augment(modelCVE) %>% 
  mutate(index = 1:n()) 
ggplot(model.data, aes(index, .std.resid)) + 
  geom_point(aes(color = BinCBT), alpha = .5) +
  theme_bw()

model.data <- augment(modelYara) %>% 
  mutate(index = 1:n()) 
ggplot(model.data, aes(index, .std.resid)) + 
  geom_point(aes(color = BinYara), alpha = .5) +
  theme_bw()

vif(modelCVE)
vif(modelYara)


#Spearman's rho for rank correlation
cor.test(data$cwe_checker,data$size,method="spearman")
cor.test(data[,"yara_rules"],data$size,method="spearman")
cor.test(data[,"cve_bin_tool"],data$size,method="spearman")

### Kruskal wallis for non-parametric one way ANOVA

#static, with and without accounting for size
kruskal.test(norm_cwe_checker ~ static, data = data)
kruskal.test(cwe_checker ~ static, data = data)
kruskal.test(yara_rules ~ static, data = data)
kruskal.test(norm_yara_rules ~ static, data = data)
kruskal.test(cve_bin_tool ~ static, data = data)
kruskal.test(norm_cve_bin_tool ~ static, data = data)

#Compiler,with and without accounting for size
kruskal.test(norm_cwe_checker ~ compiler, data = data)
kruskal.test(cwe_checker ~ compiler, data = data)
kruskal.test(yara_rules ~ compiler, data = data)
kruskal.test(norm_yara_rules ~ compiler, data = data)
kruskal.test(cve_bin_tool ~ compiler, data = data)
kruskal.test(norm_cve_bin_tool ~ compiler, data = data)

#median-based linear models based on Siegel repeated medians
lm.cwe = mblm(cwe_checker ~ size,data=data,repeated=TRUE)
lm.yara = mblm(yara_rules ~ size,data=data,repeated=TRUE)
lm.cve = mblm(cve_bin_tool ~ size,data=data,repeated=TRUE)
summary(lm.cwe)
summary(lm.yara)
summary(lm.cve)

data[,!names(data) %in% c("binary")] %>% ggpairs(upper = list(continuous = wrap("cor", method = "spearman")), diag = list(continuous = function(...) ggally_densityDiag(...) + theme(axis.text = element_blank(), axis.ticks = element_blank())))




