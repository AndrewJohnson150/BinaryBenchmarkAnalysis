data = read.csv("Data.csv")
data[,"compiler"] <- as.factor(data[,"compiler"])
data[,"static"] <- as.factor(data[,"static"])

summary(data[,-which(names(data)=="binary")])

ggpairs(data[,!names(data) %in% c("binary")],aes(colour=static,alpha=0.5))
ggpairs(data[,!names(data) %in% c("binary")])


data[,c("size","static","compiler","cwe_checker")] %>% ggpairs(upper = list(continuous = wrap("cor", method = "spearman")), diag = list(continuous = function(...) ggally_densityDiag(...) + theme(axis.text = element_blank(), axis.ticks = element_blank())))
data[,c("size","static","compiler","yara_rules")]%>% ggpairs(upper = list(continuous = wrap("cor", method = "spearman")), diag = list(continuous = function(...) ggally_densityDiag(...) + theme(axis.text = element_blank(), axis.ticks = element_blank())))
data[,c("size","static","compiler","cve_bin_tool")]%>% ggpairs(upper = list(continuous = wrap("cor", method = "spearman")), diag = list(continuous = function(...) ggally_densityDiag(...) + theme(axis.text = element_blank(), axis.ticks = element_blank())))

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


modelCWE <- lm(log(cwe_checker)~size*compiler*static,data=data)
plot(modelCWE)
(anova(modelCWE))
summary(modelCWE)


modelYara <- lm(data[,"yara_rules"]~size*compiler*static,data=data)
(anova(modelYara))

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
