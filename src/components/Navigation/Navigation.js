import React, {Fragment} from 'react';

import {NavBar, NavDivider, NavGroup, NavHeader} from './NavBar/';
import {Button} from '../util/Button/Button';
import NavLink from './NavLink/NavLink';
import {Auth} from '../../data/resource/auth';
import {Link} from 'react-router-dom';
import {FaCode, FaGithub, FaLinkedin, FaSearch, FaSignOutAlt, FaTachometerAlt, FaUserAlt,} from 'react-icons/fa';
import styles from './Navigation.module.css'
import config from '../../config'

const ExternalLink = ({href, icon, title}) => {
    if (href) {
        return (
            <>
                <a href={href}>
                    {React.cloneElement(icon, {size: 25, title})}
                </a>&nbsp;
            </>
        )
    }
    return null;
}

class Navigation extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            auth: Auth,
            user: {}
        };
        this.updateUser = this.updateUser.bind(this);
    }

    componentDidMount() {
        Auth.onChange(this.updateUser);
        Auth.getUser().then(e => {
            this.setState({
                user: e
            });
        });
    }

    updateUser(user) {
        this.setState({user});
    }

    render() {
        return (
            <NavBar>
                <NavGroup align={'left'}>
                    <NavHeader>
                        <Link to={'/'}>{config.title}</Link>
                    </NavHeader>
                    <NavDivider/>
                    <NavLink to="/" icon={<FaCode/>} label="Posts"/>
                    <NavLink to="/tag/" icon={<FaSearch/>} label="Search"/>
                </NavGroup>
                <NavGroup align={'right'}>
                    <NavDivider/>
                    {this.state.auth.isLoggedIn() ? (
                        <Fragment>
                            <NavLink icon={<FaTachometerAlt/>} to="/admin" label="Dashboard"/>
                            <NavDivider/>
                            <Button minimal icon={<FaUserAlt/>} text={this.state.user.username}/>
                            <Button minimal onClick={this.state.auth.logout} icon={<FaSignOutAlt/>} text='Logout'/>
                        </Fragment>
                    ) : (
                        <div className={styles.externalIcons}>
                            <ExternalLink title={"Github"} href={config.externalLinks.github} icon={<FaGithub/>}/>
                            <ExternalLink title={"LinkedIn"} href={config.externalLinks.linkedin} icon={<FaLinkedin/>}/>
                        </div>
                    )}
                </NavGroup>
            </NavBar>
        )
    }
}

export default Navigation;
