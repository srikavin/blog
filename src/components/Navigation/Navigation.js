import React, {Fragment} from 'react';

import {NavBar, NavDivider, NavGroup, NavHeader} from './NavBar/';
import {Button} from '../util/Button/Button';
import NavLink from './NavLink/NavLink';
import {Auth} from '../../data/resource/auth';
import {Link} from 'react-router-dom';
import {FaCode, FaGithub, FaQuestionCircle, FaSearch, FaSignOutAlt, FaTachometerAlt, FaUserAlt} from 'react-icons/fa';
import './Navigation.css'
import config from '../../config'

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

    redirect(url) {
        return () => {
            window.open(url, '_blank')
        }
    }

    render() {
        return (
            <NavBar>
                <NavGroup align={'left'}>
                    <NavHeader>
                        <Link to={'/'}>{config.brandName}</Link>
                    </NavHeader>
                    <NavDivider/>
                    <NavLink to="/" icon={<FaQuestionCircle/>} label="About"/>
                    <NavLink to="/blog" icon={<FaCode/>} label="Blog"/>
                    <NavLink to="/blog/tag/" icon={<FaSearch/>} label="Search"/>
                </NavGroup>
                <NavGroup align={'right'}>
                    {this.state.auth.isLoggedIn() ? (
                        <Fragment>
                            <NavLink icon={<FaTachometerAlt/>} to="/admin" label="Dashboard"/>
                            <NavDivider/>
                            <Button minimal icon={<FaUserAlt/>} text={this.state.user.username}/>
                            <Button minimal onClick={this.state.auth.logout} icon={<FaSignOutAlt/>} text='Logout'/>
                        </Fragment>
                    ) : (
                        <div className={'externalIcons'}>
                            <a href={'https://github.com/srikavin'}><FaGithub className={'navExternIconLink'}
                                                                              size={25}/></a>&nbsp;
                        </div>
                    )}
                </NavGroup>
            </NavBar>
        )
    }
}

export default Navigation;